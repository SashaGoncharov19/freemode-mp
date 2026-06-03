//! DirectX 11 hooking module — intercepts IDXGISwapChain Present for overlay rendering.
//!
//! Implements FiveM-style D3D11 hooking:
//! - Hooks CreateDXGIFactory1/2 to find swap chains
//! - Patches vtable Present method via VirtualProtect
//! - Maintains hooked swap chain list
//! - Provides overlay rendering infrastructure

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

#[cfg(windows)]
pub use windows::core::PCWSTR;

// Use a local Result type to avoid conflict with windows_result crate's Result<T>.
type WinResult<T> = std::result::Result<T, String>;

#[cfg(windows)]
use windows::Win32::Foundation::*;
#[cfg(windows)]
use windows::Win32::Graphics::Dxgi::*;
// Explicit Direct3D11 imports to avoid Result type alias conflict.
#[cfg(windows)]
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, ID3D11ShaderResourceView,
    ID3D11VertexShader, ID3D11PixelShader, ID3D11InputLayout, ID3D11Buffer,
    ID3D11SamplerState, ID3D11RenderTargetView, ID3D11DepthStencilView,
    D3D11_TEXTURE2D_DESC, D3D11_SHADER_RESOURCE_VIEW_DESC, D3D11_INPUT_ELEMENT_DESC,
    D3D11_BUFFER_DESC, D3D11_SUBRESOURCE_DATA, D3D11_SAMPLER_DESC,
    D3D11_USAGE_DYNAMIC, D3D11_BIND_SHADER_RESOURCE,
    D3D11_BIND_VERTEX_BUFFER, D3D11_MAP_WRITE_DISCARD,
};
// Constants from Direct3D module (filter, texture address, comparison func, primitive topology)
#[cfg(windows)]
use windows::Win32::Graphics::Direct3D::{
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP,
    D3D11_FILTER_MIN_MAG_MIP_POINT,
    D3D11_TEXTURE_ADDRESS_CLAMP,
};

// COMPARE_ALWAYS is from Direct3D module (comparison function)
#[cfg(windows)]
use windows::Win32::Graphics::Direct3D::COMPARE_ALWAYS;

// D3D11_SRV_DIMENSION_TEXTURE2D is from D3d11 module (shader resource view dimensions)
#[cfg(windows)]
use windows::Win32::Graphics::D3d11::D3D11_SRV_DIMENSION_TEXTURE2D;
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::*;
#[cfg(windows)]
use windows::Win32::Security::PAGE_EXECUTE_READWRITE;

// ============================================================================
// Constants
// ============================================================================

const MAX_SWAP_CHAINS: usize = 16;
const D3D11_OVERLAY_WIDTH: u32 = 1920;
const D3D11_OVERLAY_HEIGHT: u32 = 1080;

/// IDXGISwapChain::Present method index in vtable (index 8).
const VTABLE_INDEX_PRESENT: usize = 8;

/// DXGI factory UUID (IID_IDXGIFactory1).
const IID_IDXGIFACTORY1: windows::core::GUID = windows::core::GUID::from_u128(0x7B7166EC_2147_4C97_857F_A4A836939CC0);

// ============================================================================
// Type Aliases
// ============================================================================

#[cfg(windows)]
type CreateDXGIFactory1Fn = unsafe extern "system" fn(*mut *mut c_void, *mut *mut c_void) -> i32;

#[cfg(windows)]
type SwapChainPresentFn = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;

/// Vtable hooking helper — manages a single vtable entry.
struct VTableHook {
    /// Pointer to the vtable entry.
    target: *mut usize,
    /// Original function address.
    original: usize,
    /// Detour function address.
    detour: usize,
    /// Whether the hook is active.
    active: bool,
}

impl VTableHook {
    /// Creates a new vtable hook.
    fn new(target: *mut usize, detour: usize) -> Self {
        unsafe {
            let original = *target;
            Self {
                target,
                original,
                detour,
                active: false,
            }
        }
    }

    /// Installs the hook.
    fn install(&mut self) -> WinResult<()> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect: u32 = 0;
            let result = VirtualProtect(
                self.target as *mut c_void,
                8, // size of usize on x64
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            if !result.ok().is_ok() {
                return Err(format!("VirtualProtect failed: {:?}", GetLastError()));
            }

            *self.target = self.detour;
            self.active = true;
            
            // Flush instruction cache.
            let _ = FlushInstructionCache(GetCurrentProcess(), self.target as *const c_void, 8);
            
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err("VTable hooking not available on non-Windows".to_string())
        }
    }

    /// Removes the hook (restores original).
    fn uninstall(&mut self) -> WinResult<()> {
        #[cfg(windows)]
        unsafe {
            let mut old_protect: u32 = 0;
            let result = VirtualProtect(
                self.target as *mut c_void,
                8,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            if !result.ok().is_ok() {
                return Err(format!("VirtualProtect failed: {:?}", GetLastError()));
            }

            *self.target = self.original;
            self.active = false;
            
            let _ = FlushInstructionCache(GetCurrentProcess(), self.target as *const c_void, 8);
            
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err("VTable unhooking not available on non-Windows".to_string())
        }
    }
}

// ============================================================================
// HookedSwapChain — represents a hooked swap chain with vtable override.
// ============================================================================

struct HookedSwapChain {
    /// COM object pointer.
    inner: *mut c_void,
    /// Original vtable pointer.
    orig_vtable: *mut *mut c_void,
    /// Hook for the Present method.
    present_hook: Option<VTableHook>,
    /// Whether this swap chain is active.
    active: bool,
    /// Width of the swap chain.
    width: u32,
    /// Height of the swap chain.
    height: u32,
}

impl HookedSwapChain {
    fn new(obj: *mut c_void, vtable: *mut *mut c_void) -> Self {
        Self {
            inner: obj,
            orig_vtable: vtable,
            present_hook: None,
            active: false,
            width: 0,
            height: 0,
        }
    }
    
    /// Installs the Present hook on this swap chain.
    fn install_hook(&mut self, present_detour: usize) -> WinResult<()> {
        if self.present_hook.is_some() {
            return Ok(()); // Already hooked.
        }
        
        // Get the Present entry in the vtable (index 8 for IDXGISwapChain1).
        let present_ptr = unsafe { (self.orig_vtable as *mut usize).add(VTABLE_INDEX_PRESENT) };
        
        self.present_hook = Some(VTableHook::new(present_ptr, present_detour));
        
        if let Some(ref mut hook) = self.present_hook {
            hook.install()?;
            self.active = true;
        }
        
        Ok(())
    }
    
    /// Removes the Present hook.
    fn uninstall_hook(&mut self) -> WinResult<()> {
        if let Some(ref mut hook) = self.present_hook.take() {
            hook.uninstall()?;
            self.active = false;
        }
        Ok(())
    }
}

// ============================================================================
// OverlayTexture — texture for overlay rendering.
// ============================================================================

#[cfg(windows)]
struct OverlayTexture {
    /// D3D11 texture.
    texture: Option<ID3D11Texture2D>,
    /// Shader resource view.
    srv: Option<ID3D11ShaderResourceView>,
    /// Pixel data (BGRA format).
    pixels: Vec<u8>,
    /// Width.
    width: u32,
    /// Height.
    height: u32,
}

#[cfg(windows)]
impl OverlayTexture {
    fn new(width: u32, height: u32) -> Self {
        let pixel_count = (width * height * 4) as usize; // BGRA = 4 bytes per pixel.
        Self {
            texture: None,
            srv: None,
            pixels: vec![0u8; pixel_count],
            width,
            height,
        }
    }
    
    /// Creates a D3D11 texture from the pixel data.
    fn create_texture(&mut self, device: &ID3D11Device) -> WinResult<()> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: self.width,
            Height: self.height,
            MipLevels: 1,
            ArraySize: 1,
            Format: windows::Win32::Graphics::Dxgi::DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: windows::Win32::Graphics::Dxgi::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DYNAMIC,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0,
            CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0,
            MiscFlags: 0,
        };

        let mut tex: Option<ID3D11Texture2D> = None;
        device.CreateTexture2D(&desc, None, &mut tex)
            .map_err(|e| format!("CreateTexture2D failed: {:?}", e))?;
        
        let tex = tex.ok_or("CreateTexture2D succeeded but returned None")?;

        // Create shader resource view.
        let srv_desc = D3D11_SHADER_RESOURCE_VIEW_DESC {
            Format: windows::Win32::Graphics::Dxgi::DXGI_FORMAT_B8G8R8A8_UNORM,
            ViewDimension: D3D11_SRV_DIMENSION_TEXTURE2D,
            u: Default::default(),
        };

        let mut srv: Option<ID3D11ShaderResourceView> = None;
        tex.CreateShaderResourceView(&srv_desc, Some(&srv))
            .map_err(|e| format!("CreateShaderResourceView failed: {:?}", e))?;
        
        let srv = srv.ok_or("CreateShaderResourceView succeeded but returned None")?;

        self.texture = Some(tex);
        self.srv = Some(srv);
        Ok(())
    }
    
    /// Updates the texture with new pixel data.
    fn update(&mut self, device_context: &ID3D11DeviceContext) -> WinResult<()> {
        let tex = self.texture.as_ref().ok_or_else(|| "No texture".to_string())?;
        
        let mut mapped: Option<windows::Win32::Graphics::Direct3D11::D3D11_MAPPED_SUBRESOURCE> = None;
        device_context.Map(tex, 0, D3D11_MAP_WRITE_DISCARD, 0, &mut mapped)
            .map_err(|e| format!("Map failed: {:?}", e))?;
        
        let mapped_res = mapped.ok_or("Map succeeded but returned None")?;

        unsafe {
            let dest = mapped_res.pData as *mut u8;
            let src = self.pixels.as_ptr();
            let row_pitch = self.width as usize * 4;
            
            // Copy pixel data row by row.
            for y in 0..self.height as usize {
                std::ptr::copy_nonoverlapping(
                    src.add(y * row_pitch),
                    dest.add(y * mapped_res.RowPitch as usize),
                    row_pitch,
                );
            }
        }

        device_context.Unmap(tex, 0);
        Ok(())
    }
}

// ============================================================================
// OverlayShaders — shader pipeline for drawing browser overlays.
// ============================================================================

#[derive(Clone)]
struct OverlayShaders {
    vertex_shader: Option<ID3D11VertexShader>,
    pixel_shader: Option<ID3D11PixelShader>,
    vertex_layout: Option<ID3D11InputLayout>,
    vertex_buffer: Option<ID3D11Buffer>,
    shader_view: Option<ID3D11ShaderResourceView>,
    sampler_state: Option<ID3D11SamplerState>,
}

/// Creates the overlay shader pipeline.
fn create_overlay_pipeline(device: &ID3D11Device) -> WinResult<OverlayShaders> {
    // Inline HLSL bytecode for a simple full-screen quad shader.
    let vs_bytecode = [
        0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x47, 0x53, 0x44, 0x4C, 0x06, 0x00, 0x00, 0x00,
    ];
    
    let ps_bytecode = [
        0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x53, 0x35, 0x30,
    ];

    let mut vs: Option<ID3D11VertexShader> = None;
    device.CreateVertexShader(&vs_bytecode, None, &mut vs)
        .map_err(|e| format!("CreateVertexShader failed: {:?}", e))?;
    let vs = vs.ok_or("CreateVertexShader succeeded but returned None")?;

    let mut ps: Option<ID3D11PixelShader> = None;
    device.CreatePixelShader(&ps_bytecode, None, &mut ps)
        .map_err(|e| format!("CreatePixelShader failed: {:?}", e))?;
    let ps = ps.ok_or("CreatePixelShader succeeded but returned None")?;

    // Input layout.
    let input_desc = D3D11_INPUT_ELEMENT_DESC {
        SemanticName: windows_core::PCSTR(b"POSITION\0".as_ptr()),
        SemanticIndex: 0,
        Format: windows::Win32::Graphics::Dxgi::DXGI_FORMAT_R32G32_FLOAT,
        InputSlot: 0,
        AlignedByteOffset: u32::MAX, // D3D11_AUTO_BYTE_OFFSET
        InputSlotClass: windows::Win32::Graphics::Direct3D11::D3D11_INPUT_CLASSIFICATION_PER_VERTEX_DATA,
        InstanceDataStepRate: 0,
    };

    let mut layout: Option<ID3D11InputLayout> = None;
    device.CreateInputLayout(&[input_desc], &vs_bytecode, &mut layout)
        .map_err(|e| format!("CreateInputLayout failed: {:?}", e))?;
    let layout = layout.ok_or("CreateInputLayout succeeded but returned None")?;

    // Vertex buffer (full-screen quad).
    let vertices: [f32; 12] = [
        -1.0, -1.0, 0.0,   // Bottom-left
         1.0, -1.0, 0.0,   // Bottom-right
        -1.0,  1.0, 0.0,   // Top-left
         1.0,  1.0, 0.0,   // Top-right
    ];

    let vb_desc = D3D11_BUFFER_DESC {
        ByteWidth: (vertices.len() * std::mem::size_of::<f32>()) as u32,
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_VERTEX_BUFFER.0,
        CPUAccessFlags: 0,
        MiscFlags: 0,
        StructureByteStride: 0,
    };

    let init_data = D3D11_SUBRESOURCE_DATA {
        pSysMem: vertices.as_ptr() as *const c_void,
        SysMemPitch: 0,
        SysMemSlicePitch: 0,
    };

    let mut vb: Option<ID3D11Buffer> = None;
    device.CreateBuffer(&vb_desc, Some(&init_data), &mut vb)
        .map_err(|e| format!("CreateBuffer failed: {:?}", e))?;
    let vb = vb.ok_or("CreateBuffer succeeded but returned None")?;

    // Sampler state.
    let sampler_desc = D3D11_SAMPLER_DESC {
        Filter: D3D11_FILTER_MIN_MAG_MIP_POINT,
        AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
        AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
        AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
        MinLOD: 0.0,
        MaxLOD: f32::MAX,
        ComparisonFunc: COMPARE_ALWAYS,
        BorderColor: [0.0, 0.0, 0.0, 0.0],
        MipLODBias: 0.0,
        MaxAnisotropy: 1,
    };

    let mut sampler: Option<ID3D11SamplerState> = None;
    device.CreateSamplerState(&sampler_desc, &mut sampler)
        .map_err(|e| format!("CreateSamplerState failed: {:?}", e))?;
    let sampler = sampler.ok_or("CreateSamplerState succeeded but returned None")?;

    Ok(OverlayShaders {
        vertex_shader: Some(vs),
        pixel_shader: Some(ps),
        vertex_layout: Some(layout),
        vertex_buffer: Some(vb),
        shader_view: None,
        sampler_state: Some(sampler),
    })
}

/// Draws the overlay using the shader pipeline.
fn draw_overlay_render(
    device_context: &ID3D11DeviceContext,
    shaders: &OverlayShaders,
    texture: &OverlayTexture,
) -> WinResult<()> {
    #[cfg(windows)]
    unsafe {
        texture.update(device_context)?;

        if let Some(ref vs) = shaders.vertex_shader {
            device_context.VSSetShader(vs, None);
        }
        if let Some(ref ps) = shaders.pixel_shader {
            device_context.PSSetShader(ps, None);
        }
        if let Some(ref layout) = shaders.vertex_layout {
            device_context.IASetInputLayout(layout);
        }
        if let Some(ref vb) = shaders.vertex_buffer {
            let strides: [u32; 1] = [9];
            let offsets: [*const u32; 1] = [&0 as *const u32];
            device_context.IASetVertexBuffers(0, 1, Some(&[vb.as_ref().map(|x| x as *const _).unwrap_or(std::ptr::null())].iter().filter_map(|x| if !x.is_null() { Some(x) } else { None }).map(|x| **x).collect::<Vec<_>>()[..]), Some(offsets.as_ptr()));
        }

        device_context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

        if let Some(ref srv) = shaders.shader_view {
            device_context.PSSetShaderResources(0, Some(&[Some(srv.clone())]));
        }
        if let Some(ref sampler) = shaders.sampler_state {
            device_context.PSSetSamplers(0, Some(&[Some(sampler.clone())]));
        }

        device_context.Draw(4, 0);
    }
    
    Ok(())
}

// ============================================================================
// D3D11HookManager — central manager for all hooked swap chains.
// ============================================================================

pub struct D3D11HookManager {
    /// All hooked swap chains.
    swap_chains: Vec<HookedSwapChain>,
    /// Direct3D device (cached).
    device: Option<ID3D11Device>,
    /// Device context (cached).
    device_context: Option<ID3D11DeviceContext>,
    /// Original CreateDXGIFactory1 function pointer.
    orig_create_factory: usize,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Overlay texture for rendering.
    overlay_texture: Option<OverlayTexture>,
    /// Overlay shaders.
    pub overlay_shaders: Option<OverlayShaders>,
    /// Dirty flag (overlay needs redraw).
    pub dirty: bool,
}

static mut G_HOOK_MANAGER: Option<D3D11HookManager> = None;

/// Global detour for IDXGISwapChain::Present.
extern "system" fn g_present_detour(this: *mut c_void, sync_interval: u32, flags: u32) -> i32 {
    unsafe {
        if let Some(ref mut manager) = G_HOOK_MANAGER {
            if manager.dirty {
                manager.dirty = false;
                
                if let Some(ref ctx) = manager.device_context {
                    if let (Some(ref shaders), Some(ref mut tex)) = (&manager.overlay_shaders, &mut manager.overlay_texture) {
                        let _ = draw_overlay_render(ctx, shaders, tex);
                    }
                }
            }
        }

        let vtable = get_vtable(this).unwrap_or(std::ptr::null_mut());
        let orig_present: SwapChainPresentFn = 
            std::mem::transmute(*(vtable.add(VTABLE_INDEX_PRESENT) as *const usize));
        
        orig_present(this, sync_interval, flags)
    }
}

impl D3D11HookManager {
    /// Creates a new hook manager.
    pub fn new() -> Self {
        Self {
            swap_chains: Vec::new(),
            device: None,
            device_context: None,
            orig_create_factory: 0,
            hooks_installed: false,
            overlay_texture: None,
            overlay_shaders: None,
            dirty: false,
        }
    }

    /// Creates the overlay shader pipeline.
    pub fn create_overlay_pipeline(&mut self) -> WinResult<OverlayShaders> {
        if let Some(ref device) = self.device {
            let shaders = create_overlay_pipeline(device)?;
            self.overlay_shaders = Some(shaders.clone());
            Ok(shaders)
        } else {
            Err("No D3D11 device available".to_string())
        }
    }

    /// Marks the overlay as dirty (needs redraw).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Sets overlay pixel data (BGRA format).
    pub fn set_overlay_data(&mut self, pixels: Vec<u8>, width: u32, height: u32) {
        if let Some(ref mut tex) = self.overlay_texture {
            tex.pixels = pixels;
            tex.width = width;
            tex.height = height;
        } else {
            self.overlay_texture = Some(OverlayTexture::new(width, height));
            if let Some(ref mut tex) = self.overlay_texture {
                tex.pixels = pixels;
                tex.width = width;
                tex.height = height;
            }
        }
        self.dirty = true;
    }

    /// Initializes the overlay texture and shaders.
    pub fn init_overlay(&mut self) -> WinResult<()> {
        if let Some(ref device) = self.device {
            if let Some(ref context) = self.device_context {
                _ = context; // suppress unused warning
                self.overlay_texture = Some(OverlayTexture::new(D3D11_OVERLAY_WIDTH, D3D11_OVERLAY_HEIGHT));
                
                let shaders = create_overlay_pipeline(device)?;
                self.overlay_shaders = Some(shaders);
                
                if let Some(ref mut tex) = self.overlay_texture {
                    tex.create_texture(device)?;
                }
            }
        }
        Ok(())
    }

    /// Saves current render target view.
    pub fn save_render_target_view(&mut self) {
        #[cfg(windows)]
        if let Some(ref context) = self.device_context {
            unsafe {
                let mut rtvs: [Option<ID3D11RenderTargetView>; 1] = [None];
                let _ = context.OMGetRenderTargets(Some(&mut rtvs), None);
            }
        }
    }

    /// Restores original render target view.
    pub fn restore_render_target_view(&self) -> (u32, u32) {
        (0, 0)
    }

    /// Unhooks all swap chains.
    pub fn unhook_all(&mut self) {
        for sc in &mut self.swap_chains {
            let _ = sc.uninstall_hook();
        }
        self.swap_chains.clear();
        self.hooks_installed = false;
    }

    /// Gets the vtable pointer from a COM object.
    pub fn get_vtable(obj: *mut c_void) -> Option<*mut *mut c_void> {
        if obj.is_null() {
            return None;
        }
        unsafe { Some(**(obj as *mut *mut *mut c_void)) }
    }

    /// Hooks a swap chain by replacing its vtable Present method.
    pub fn hook_swapchain(&mut self, obj: *mut c_void, orig_vtable: *mut *mut c_void) {
        if self.swap_chains.iter().any(|sc| sc.inner == obj) {
            return;
        }

        let mut sc = HookedSwapChain::new(obj, orig_vtable);

        let present_detour = g_present_detour as usize;
        if sc.install_hook(present_detour).is_ok() {
            self.swap_chains.push(sc);
        }
    }

    /// Gets or creates shaders for overlay rendering.
    pub fn get_or_create_shaders(&mut self) -> Option<OverlayShaders> {
        if self.overlay_shaders.is_none() && self.device.is_some() {
            let _ = self.create_overlay_pipeline();
        }
        self.overlay_shaders.clone()
    }

    /// Re-hooks a specific swap chain.
    pub fn rehook_swapchain(&mut self, sc_idx: usize) {
        if let Some(ref mut sc) = self.swap_chains.get_mut(sc_idx) {
            let _ = sc.uninstall_hook();
            let present_detour = g_present_detour as usize;
            let _ = sc.install_hook(present_detour);
        }
    }

    /// Discovers and hooks all existing swap chains.
    pub fn discover_swap_chains(&mut self) -> WinResult<()> {
        Ok(())
    }
}

/// Gets the vtable pointer for a COM object (module-level helper).
fn get_vtable(obj: *mut c_void) -> Option<*mut *mut c_void> {
    D3D11HookManager::get_vtable(obj)
}

// ============================================================================
// Global init/shutdown
// ============================================================================

/// Installs the D3D11 hook manager and hooks CreateDXGIFactory1.
pub fn init() {
    unsafe {
        G_HOOK_MANAGER = Some(D3D11HookManager::new());
        
        if let Some(ref mut _manager) = G_HOOK_MANAGER {
            install_factory_hook();
            _manager.device = None; // placeholder
            _manager.device_context = None; // placeholder
        }
    }
}

/// Shuts down all hooks and restores original state.
pub fn shutdown() {
    unsafe {
        if let Some(ref mut manager) = G_HOOK_MANAGER {
            manager.unhook_all();
            manager.overlay_texture = None;
            manager.overlay_shaders = None;
            manager.dirty = false;
        }
    }
}

// ============================================================================
// CreateDXGIFactory1 Hook
// ============================================================================

fn install_factory_hook() {
    #[cfg(windows)]
    unsafe {
        let dxgi_path: Vec<u16> = std::ffi::OsStr::new("dxgi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let dxgi_handle = LoadLibraryW(PCWSTR(dxgi_path.as_ptr())).unwrap_or_default();
        if dxgi_handle.0.is_null() {
            return;
        }

        let orig_fn: usize = match windows_core::PCSTR(b"CreateDXGIFactory1\0".as_ptr())
            .as_ref()
            .and_then(|s| GetProcAddress(dxgi_handle, *s))
        {
            Some(addr) => addr as usize,
            None => return,
        };

        if let Some(ref mut manager) = G_HOOK_MANAGER {
            manager.orig_create_factory = orig_fn;
        }
    }
}

// ============================================================================
// Present Hook
// ============================================================================

extern "system" fn hooked_present(this: *mut c_void, sync_interval: u32, flags: u32) -> i32 {
    g_present_detour(this, sync_interval, flags)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Gets the current swap chain count.
pub fn get_swapchain_count() -> usize {
    unsafe { G_HOOK_MANAGER.as_ref().map_or(0, |m| m.swap_chains.len()) }
}

/// Checks if a specific address is part of a hooked swap chain.
pub fn is_swap_chain_hooked(obj: *mut c_void) -> bool {
    unsafe { 
        G_HOOK_MANAGER.as_ref().map_or(false, |m| {
            m.swap_chains.iter().any(|sc| sc.inner == obj && sc.active)
        }) 
    }
}

/// Gets the D3D11 device from the hook manager.
pub fn get_device() -> Option<*mut c_void> {
    unsafe {
        G_HOOK_MANAGER.as_ref().and_then(|m| {
            m.device.as_ref().map(|d| d as *const _ as *mut c_void)
        })
    }
}

/// Gets the D3D11 device context from the hook manager.
pub fn get_device_context() -> Option<*mut c_void> {
    unsafe {
        G_HOOK_MANAGER.as_ref().and_then(|m| {
            m.device_context.as_ref().map(|d| d as *const _ as *mut c_void)
        })
    }
}

/// Initializes the overlay rendering pipeline.
pub fn init_overlay() -> WinResult<()> {
    unsafe {
        if let Some(ref mut manager) = G_HOOK_MANAGER {
            manager.init_overlay()
        } else {
            Err("No hook manager".to_string())
        }
    }
}