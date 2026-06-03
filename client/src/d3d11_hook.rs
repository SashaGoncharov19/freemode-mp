//! DirectX 11 hooking module — intercepts IDXGISwapChain Present for overlay rendering.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

type WinResult<T> = std::result::Result<T, String>;

#[cfg(windows)]
use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::Graphics::Dxgi::*;
#[cfg(windows)]
use windows::Win32::Graphics::Dxgi::Common::*;
#[cfg(windows)]
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, ID3D11ShaderResourceView,
    ID3D11VertexShader, ID3D11PixelShader, ID3D11InputLayout, ID3D11Buffer,
    ID3D11SamplerState,
    D3D11_TEXTURE2D_DESC, D3D11_SHADER_RESOURCE_VIEW_DESC, D3D11_INPUT_ELEMENT_DESC,
    D3D11_BUFFER_DESC, D3D11_SUBRESOURCE_DATA, D3D11_SAMPLER_DESC,
    D3D11_USAGE_DYNAMIC,
    D3D11_MAP_WRITE_DISCARD, D3D11_USAGE_DEFAULT,
    D3D11_MAPPED_SUBRESOURCE,
    D3D11_BIND_VERTEX_BUFFER,
};
// Raw constants since windows crate v0.58 doesn't export all enums as values.
const D3D11_INPUT_CLASSIFICATION_PER_VERTEX_DATA: i32 = 1;
const D3D11_BIND_SHADER_RESOURCE_RAW: u32 = 0x10000;
const D3D11_CPU_ACCESS_WRITE_RAW: u32 = 0x10000;

use windows::Win32::Graphics::Direct3D::{
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP,
};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentProcess;
#[cfg(windows)]
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};

const MAX_SWAP_CHAINS: usize = 16;
const D3D11_OVERLAY_WIDTH: u32 = 1920;
const D3D11_OVERLAY_HEIGHT: u32 = 1080;
const VTABLE_INDEX_PRESENT: usize = 8;

#[cfg(windows)]
type SwapChainPresentFn = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;

struct VTableHook {
    target: *mut usize,
    original: usize,
    detour: usize,
    active: bool,
}

impl VTableHook {
    fn new(target: *mut usize, detour: usize) -> Self {
        unsafe { Self { target, original: *target, detour, active: false } }
    }
    fn install(&mut self) -> WinResult<()> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(self.target as *const c_void, 8, PAGE_EXECUTE_READWRITE, &mut old_protect).is_ok() { return Err("VirtualProtect failed".to_string()); }
            *self.target = self.detour; self.active = true;
            let hproc = GetCurrentProcess();
            let _ = FlushInstructionCache(hproc, Some(self.target as *const c_void), 8);
            Ok(())
        }
        #[cfg(not(windows))]
        { let _ = self; Err("Not available".to_string()); }
    }
    fn uninstall(&mut self) -> WinResult<()> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(self.target as *const c_void, 8, PAGE_EXECUTE_READWRITE, &mut old_protect).is_ok() { return Err("VirtualProtect failed".to_string()); }
            *self.target = self.original; self.active = false;
            let hproc = GetCurrentProcess();
            let _ = FlushInstructionCache(hproc, Some(self.target as *const c_void), 8);
            Ok(())
        }
        #[cfg(not(windows))]
        { let _ = self; Err("Not available".to_string()); }
    }
}

struct HookedSwapChain { inner: *mut c_void, orig_vtable: *mut *mut c_void, present_hook: Option<VTableHook>, active: bool, width: u32, height: u32 }
impl HookedSwapChain {
    fn new(obj: *mut c_void, vtable: *mut *mut c_void) -> Self { Self { inner: obj, orig_vtable: vtable, present_hook: None, active: false, width: 0, height: 0 } }
    fn install_hook(&mut self, detour: usize) -> WinResult<()> {
        if self.present_hook.is_some() { return Ok(()); }
        let p = unsafe { (self.orig_vtable as *mut usize).add(VTABLE_INDEX_PRESENT) };
        self.present_hook = Some(VTableHook::new(p, detour));
        if let Some(ref mut h) = self.present_hook { h.install()?; self.active = true; }
        Ok(())
    }
    fn uninstall_hook(&mut self) -> WinResult<()> {
        if let Some(ref mut h) = self.present_hook.take() { h.uninstall()?; self.active = false; }
        Ok(())
    }
}

#[cfg(windows)]
struct OverlayTexture { texture: Option<ID3D11Texture2D>, srv: Option<ID3D11ShaderResourceView>, pixels: Vec<u8>, width: u32, height: u32 }

#[cfg(windows)]
impl OverlayTexture {
    fn new(w: u32, h: u32) -> Self { Self { texture: None, srv: None, pixels: vec![0u8; (w * h * 4) as usize], width: w, height: h } }

    fn create_texture(&mut self, device: &ID3D11Device) -> WinResult<()> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: self.width, Height: self.height, MipLevels: 1, ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM, SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_DYNAMIC, BindFlags: D3D11_BIND_SHADER_RESOURCE_RAW, CPUAccessFlags: D3D11_CPU_ACCESS_WRITE_RAW, MiscFlags: 0,
        };
        let mut tex: Option<ID3D11Texture2D> = None;
        unsafe {
            device.CreateTexture2D(&desc, None, Some(&mut tex))
                .map_err(|e| format!("CreateTexture2D failed: {:?}", e))?;
        }
        let tex = tex.ok_or("CreateTexture2D returned None".to_string())?;

        // Build SRV desc as raw bytes.
        let mut srv_desc_bytes = [0u8; 16];
        unsafe { std::ptr::write_bytes(srv_desc_bytes.as_mut_ptr(), 0, 16); }
        srv_desc_bytes[0] = 87; srv_desc_bytes[1] = 0; srv_desc_bytes[2] = 0; srv_desc_bytes[3] = 0;
        srv_desc_bytes[4] = 3;

        let mut srv: Option<ID3D11ShaderResourceView> = None;
        unsafe {
            device.CreateShaderResourceView(&tex, Some(&srv_desc_bytes as *const u8 as *const D3D11_SHADER_RESOURCE_VIEW_DESC), Some(&mut srv))
                .map_err(|e| format!("CreateShaderResourceView failed: {:?}", e))?;
        }
        let srv = srv.ok_or("CreateShaderResourceView returned None".to_string())?;
        self.texture = Some(tex); self.srv = Some(srv);
        Ok(())
    }

    fn update(&self, ctx: &ID3D11DeviceContext) -> WinResult<()> {
        let tex = self.texture.as_ref().ok_or("No texture".to_string())?;
        let mut mapped: D3D11_MAPPED_SUBRESOURCE = unsafe { std::mem::zeroed() };
        unsafe {
            ctx.Map(tex, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped))
                .map_err(|e| format!("Map failed: {:?}", e))?;
        }
        let mapped_ptr = std::ptr::addr_of!(mapped);
        unsafe {
            let pData = (*mapped_ptr).pData as *mut u8;
            let src = self.pixels.as_ptr();
            let row_pitch = (self.width as usize) * 4;
            let pitch = (*mapped_ptr).RowPitch;
            for y in 0..self.height as usize {
                std::ptr::copy_nonoverlapping(src.add(y * row_pitch), pData.add(y * pitch as usize), row_pitch);
            }
            ctx.Unmap(tex, 0);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OverlayShaders {
    vertex_shader: Option<ID3D11VertexShader>, pixel_shader: Option<ID3D11PixelShader>,
    vertex_layout: Option<ID3D11InputLayout>, vertex_buffer: Option<ID3D11Buffer>,
    shader_view: Option<ID3D11ShaderResourceView>, sampler_state: Option<ID3D11SamplerState>,
}

fn create_overlay_pipeline(device: &ID3D11Device) -> WinResult<OverlayShaders> {
    let vs_bc = [0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x53, 0x44, 0x4C, 0x06, 0x00, 0x00, 0x00];
    let ps_bc = [0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x35, 0x30];

    let mut vs: Option<ID3D11VertexShader> = None;
    unsafe {
        device.CreateVertexShader(&vs_bc, None, Some(&mut vs))
            .map_err(|e| format!("CreateVertexShader failed: {:?}", e))?;
    }
    let vs = vs.ok_or("VS null".to_string())?;
    let mut ps: Option<ID3D11PixelShader> = None;
    unsafe {
        device.CreatePixelShader(&ps_bc, None, Some(&mut ps))
            .map_err(|e| format!("CreatePixelShader failed: {:?}", e))?;
    }
    let ps = ps.ok_or("PS null".to_string())?;

    let mut semantic_bytes = b"POSITION\0";
    let input_desc = D3D11_INPUT_ELEMENT_DESC {
        SemanticName: windows_core::PCSTR(semantic_bytes.as_ptr()), SemanticIndex: 0,
        Format: DXGI_FORMAT_R32G32_FLOAT, InputSlot: 0, AlignedByteOffset: u32::MAX,
        InputSlotClass: unsafe { windows::Win32::Graphics::Direct3D11::D3D11_INPUT_CLASSIFICATION(D3D11_INPUT_CLASSIFICATION_PER_VERTEX_DATA) }, InstanceDataStepRate: 0,
    };
    let mut layout: Option<ID3D11InputLayout> = None;
    unsafe {
        device.CreateInputLayout(&[input_desc], &vs_bc, Some(&mut layout))
            .map_err(|e| format!("CreateInputLayout failed: {:?}", e))?;
    }
    let layout = layout.ok_or("Layout null".to_string())?;

    let verts: [f32; 12] = [-1.0, -1.0, 0.0, 1.0, -1.0, 0.0, -1.0, 1.0, 0.0, 1.0, 1.0, 0.0];
    let vb_desc = D3D11_BUFFER_DESC { ByteWidth: (verts.len() * 4) as u32, Usage: D3D11_USAGE_DEFAULT, BindFlags: D3D11_BIND_SHADER_RESOURCE_RAW, CPUAccessFlags: 0, MiscFlags: 0, StructureByteStride: 0 };
    let init = D3D11_SUBRESOURCE_DATA { pSysMem: verts.as_ptr() as *const c_void, SysMemPitch: 0, SysMemSlicePitch: 0 };
    let mut vb: Option<ID3D11Buffer> = None;
    unsafe {
        device.CreateBuffer(&vb_desc, Some(&init), Some(&mut vb))
            .map_err(|e| format!("CreateBuffer failed: {:?}", e))?;
    }
    let vb = vb.ok_or("VB null".to_string())?;

    let mut samp_bytes = [0u8; 56];
    unsafe { std::ptr::write_bytes(samp_bytes.as_mut_ptr(), 0, 56); }
    samp_bytes[4] = 1; samp_bytes[8] = 1; samp_bytes[12] = 1; samp_bytes[28..32].copy_from_slice(&7u32.to_le_bytes());

    let samp_desc_ptr = &samp_bytes as *const u8 as *const D3D11_SAMPLER_DESC;
    let mut sampler: Option<ID3D11SamplerState> = None;
    unsafe {
        device.CreateSamplerState(&(*samp_desc_ptr), Some(&mut sampler))
            .map_err(|e| format!("CreateSamplerState failed: {:?}", e))?;
    }
    let sampler = sampler.ok_or("Sampler null".to_string())?;

    Ok(OverlayShaders { vertex_shader: Some(vs), pixel_shader: Some(ps), vertex_layout: Some(layout), vertex_buffer: Some(vb), shader_view: None, sampler_state: Some(sampler) })
}

fn draw_overlay_render(device_context: &ID3D11DeviceContext, shaders: &OverlayShaders, texture: &OverlayTexture) -> WinResult<()> {
    #[cfg(windows)] unsafe {
        use windows_core::Interface;
        texture.update(device_context)?;
        if let Some(ref vs) = shaders.vertex_shader { device_context.VSSetShader(vs, None); }
        if let Some(ref ps) = shaders.pixel_shader { device_context.PSSetShader(ps, None); }
        if let Some(ref lay) = shaders.vertex_layout { device_context.IASetInputLayout(lay); }
        if let Some(ref vb) = shaders.vertex_buffer {
            let vb_opt: Option<ID3D11Buffer> = Some(vb.clone());
            let ptr = std::ptr::addr_of!(vb_opt) as *const _;
            device_context.IASetVertexBuffers(0, 1, Some(ptr), None, None);
        }
        device_context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
        if let Some(ref srv) = shaders.shader_view { device_context.PSSetShaderResources(0, Some(&[Some(srv.clone())])); }
        if let Some(ref samp) = shaders.sampler_state { device_context.PSSetSamplers(0, Some(&[Some(samp.clone())])); }
        device_context.Draw(4, 0);
    }
    Ok(())
}

pub struct D3D11HookManager {
    swap_chains: Vec<HookedSwapChain>, device: Option<ID3D11Device>, device_context: Option<ID3D11DeviceContext>,
    orig_create_factory: usize, pub hooks_installed: bool, overlay_texture: Option<OverlayTexture>,
    pub overlay_shaders: Option<OverlayShaders>, pub dirty: bool,
}
static mut G_HOOK_MANAGER: Option<D3D11HookManager> = None;

extern "system" fn g_present_detour(this: *mut c_void, sync_interval: u32, flags: u32) -> i32 {
    unsafe {
        if let Some(ref mut m) = G_HOOK_MANAGER {
            if m.dirty {
                m.dirty = false;
                if let (Some(ref ctx), Some(ref sh), Some(ref mut tex)) = (&m.device_context, &m.overlay_shaders, &mut m.overlay_texture) {
                    let _ = draw_overlay_render(ctx, sh, tex);
                }
            }
        }
        let vt = get_vtable(this).unwrap_or(std::ptr::null_mut());
        let orig: SwapChainPresentFn = std::mem::transmute(*(vt.add(VTABLE_INDEX_PRESENT) as *const usize));
        orig(this, sync_interval, flags)
    }
}

impl D3D11HookManager {
    pub fn new() -> Self { Self { swap_chains: Vec::new(), device: None, device_context: None, orig_create_factory: 0, hooks_installed: false, overlay_texture: None, overlay_shaders: None, dirty: false } }
    pub fn create_overlay_pipeline(&mut self) -> WinResult<OverlayShaders> {
        if let Some(ref d) = self.device { let s = create_overlay_pipeline(d)?; self.overlay_shaders = Some(s.clone()); Ok(s) } else { Err("No device".to_string()) }
    }
    pub fn mark_dirty(&mut self) { self.dirty = true; }
    pub fn set_overlay_data(&mut self, pixels: Vec<u8>, w: u32, h: u32) {
        if let Some(ref mut t) = self.overlay_texture { t.pixels = pixels; t.width = w; t.height = h; }
        else { self.overlay_texture = Some(OverlayTexture::new(w, h)); if let Some(ref mut t) = self.overlay_texture { t.pixels = pixels; t.width = w; t.height = h; } }
        self.dirty = true;
    }
    pub fn init_overlay(&mut self) -> WinResult<()> {
        if let Some(ref d) = self.device {
            if self.device_context.is_some() {
                self.overlay_texture = Some(OverlayTexture::new(D3D11_OVERLAY_WIDTH, D3D11_OVERLAY_HEIGHT));
                let s = create_overlay_pipeline(d)?; self.overlay_shaders = Some(s);
                if let Some(ref mut t) = self.overlay_texture { t.create_texture(d)?; }
            }
        }
        Ok(())
    }
    pub fn save_render_target_view(&mut self) {}
    pub fn restore_render_target_view(&self) -> (u32, u32) { (0, 0) }
    pub fn unhook_all(&mut self) { for sc in &mut self.swap_chains { let _ = sc.uninstall_hook(); } self.swap_chains.clear(); self.hooks_installed = false; }
    pub fn get_vtable(obj: *mut c_void) -> Option<*mut *mut c_void> { if obj.is_null() { None } else { unsafe { Some(*(obj as *mut *mut *mut c_void)) } } }
    pub fn hook_swapchain(&mut self, obj: *mut c_void, orig_vtable: *mut *mut c_void) {
        if self.swap_chains.iter().any(|sc| sc.inner == obj) { return; }
        let mut sc = HookedSwapChain::new(obj, orig_vtable);
        if sc.install_hook(g_present_detour as usize).is_ok() { self.swap_chains.push(sc); }
    }
    pub fn get_or_create_shaders(&mut self) -> Option<OverlayShaders> {
        if self.overlay_shaders.is_none() && self.device.is_some() { let _ = self.create_overlay_pipeline(); }
        self.overlay_shaders.clone()
    }
    pub fn rehook_swapchain(&mut self, idx: usize) {
        if let Some(ref mut sc) = self.swap_chains.get_mut(idx) { let _ = sc.uninstall_hook(); let _ = sc.install_hook(g_present_detour as usize); }
    }
    pub fn discover_swap_chains(&mut self) -> WinResult<()> { Ok(()) }
}

fn get_vtable(obj: *mut c_void) -> Option<*mut *mut c_void> { D3D11HookManager::get_vtable(obj) }

pub fn init() { unsafe { G_HOOK_MANAGER = Some(D3D11HookManager::new()); if let Some(ref mut _m) = G_HOOK_MANAGER { install_factory_hook(); } } }
pub fn shutdown() { unsafe { if let Some(ref mut m) = G_HOOK_MANAGER { m.unhook_all(); m.overlay_texture = None; m.overlay_shaders = None; m.dirty = false; } } }

fn install_factory_hook() {
    #[cfg(windows)]
    unsafe {
        use windows_core::{PCWSTR, PCSTR};
        let dxgi_path: Vec<u16> = std::ffi::OsStr::new("dxgi.dll")
            .encode_wide().chain(std::iter::once(0u16)).collect();
        let dxgi_handle = windows::Win32::System::LibraryLoader::LoadLibraryW(PCWSTR(dxgi_path.as_ptr())).unwrap_or_default();
        if dxgi_handle.0.is_null() { return; }
        let fn_name = b"CreateDXGIFactory1\0";
        let orig_addr = windows::Win32::System::LibraryLoader::GetProcAddress(dxgi_handle, PCSTR(fn_name.as_ptr()));
        if let Some(addr) = orig_addr { if let Some(ref mut m) = G_HOOK_MANAGER { m.orig_create_factory = addr as usize; } }
    }
}

extern "system" fn hooked_present(this: *mut c_void, sync_interval: u32, flags: u32) -> i32 { g_present_detour(this, sync_interval, flags) }
pub fn get_swapchain_count() -> usize { unsafe { G_HOOK_MANAGER.as_ref().map_or(0, |m| m.swap_chains.len()) } }
pub fn is_swap_chain_hooked(obj: *mut c_void) -> bool { unsafe { G_HOOK_MANAGER.as_ref().map_or(false, |m| m.swap_chains.iter().any(|sc| sc.inner == obj && sc.active)) } }
pub fn get_device() -> Option<*mut c_void> { unsafe { G_HOOK_MANAGER.as_ref().and_then(|m| m.device.as_ref().map(|d| d as *const _ as *mut c_void)) } }
pub fn get_device_context() -> Option<*mut c_void> { unsafe { G_HOOK_MANAGER.as_ref().and_then(|m| m.device_context.as_ref().map(|d| d as *const _ as *mut c_void)) } }
pub fn init_overlay() -> WinResult<()> { unsafe { if let Some(ref mut m) = G_HOOK_MANAGER { m.init_overlay() } else { Err("No hook manager".into()) } } }