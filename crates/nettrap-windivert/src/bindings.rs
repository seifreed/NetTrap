//! WinDivert FFI bindings.
//!
//! Raw bindings to the WinDivert library for Windows packet interception.

use std::os::raw::c_void;

pub type HANDLE = *mut c_void;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindivertAddress {
    pub if_index: u32,
    pub sub_if_index: u32,
    pub direction: u8,
    pub loopback: u8,
    pub impostor: u8,
    pub checksum_failed: u8,
    pub checksum_v4: u8,
    pub checksum_v6: u8,
    pub reserved0: u8,
    pub reserved1: u8,
    pub reserved2: u8,
    pub reserved3: u8,
    pub reserved4: u8,
    pub reserved5: u8,
    pub reserved6: u8,
    pub reserved7: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertIpHdr {
    pub ver_hdrlen: u8,
    pub tos: u8,
    pub len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertIpv6Hdr {
    pub flow0: u8,
    pub flow1: u8,
    pub flow2: u8,
    pub plen: u16,
    pub nxt: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertTcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags0: u8,
    pub flags1: u8,
    pub window: u16,
    pub checksum: u16,
    pub urg_ptr: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertUdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub checksum: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertIcmpHdr {
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindivertIcmpv6Hdr {
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: u32,
}

pub const WINDIVERT_LAYER_NETWORK: i32 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: i32 = 1;

pub const WINDIVERT_FLAG_NO_IP_INPUT: u64 = 1;

pub const WINDIVERT_PACKET_SNIFF: u64 = 1;

pub const WINDIVERT_DIRECTION_OUT: u8 = 0;
pub const WINDIVERT_DIRECTION_IN: u8 = 1;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct WindivertFlags: u64 {
        const DEFAULT = 0;
        const SNIFF = WINDIVERT_PACKET_SNIFF;
        const NO_IP_INPUT = WINDIVERT_FLAG_NO_IP_INPUT;
    }
}

pub type WindivertLayer = i32;
pub type WindivertPriority = i16;

pub const WINDIVERT_IP_HDR_LEN: usize = std::mem::size_of::<WindivertIpHdr>();
pub const WINDIVERT_IPV6_HDR_LEN: usize = std::mem::size_of::<WindivertIpv6Hdr>();
pub const WINDIVERT_TCP_HDR_LEN: usize = std::mem::size_of::<WindivertTcpHdr>();
pub const WINDIVERT_UDP_HDR_LEN: usize = std::mem::size_of::<WindivertUdpHdr>();
pub const WINDIVERT_ICMP_HDR_LEN: usize = std::mem::size_of::<WindivertIcmpHdr>();
pub const WINDIVERT_ICMPV6_HDR_LEN: usize = std::mem::size_of::<WindivertIcmpv6Hdr>();

pub const IPPROTO_IP: u8 = 0;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_IPV6: u8 = 41;
pub const IPPROTO_ICMPV6: u8 = 58;

#[cfg(windows)]
pub struct WinDivert {
    handle: Option<libloading::Library>,
}

#[cfg(windows)]
impl WinDivert {
    pub fn new() -> Self {
        Self { handle: None }
    }

    pub fn open(
        &mut self,
        filter: &str,
        priority: i16,
        layer: WindivertLayer,
        flags: u64,
    ) -> Result<HANDLE, String> {
        use widestring::U16CString;

        let lib = unsafe {
            libloading::Library::new("WinDivert.dll")
                .map_err(|e| format!("Failed to load WinDivert.dll: {}", e))?
        };

        let filter_wide =
            U16CString::from_str(filter).map_err(|e| format!("Invalid filter string: {}", e))?;

        let open: libloading::Symbol<
            unsafe extern "system" fn(*const u16, WindivertLayer, i16, u64) -> HANDLE,
        > = unsafe {
            lib.get(b"WinDivertOpen\0")
                .map_err(|e| format!("Failed to get WinDivertOpen: {}", e))?
        };

        let handle = unsafe { open(filter_wide.as_ptr(), layer, priority, flags) };

        if handle.is_null() {
            return Err("WinDivertOpen returned NULL".to_string());
        }

        self.handle = Some(lib);
        Ok(handle)
    }

    pub fn recv(
        &self,
        handle: HANDLE,
        buf: &mut [u8],
        addr: &mut WindivertAddress,
    ) -> Result<u32, String> {
        let lib = self.handle.as_ref().ok_or("Library not loaded")?;

        let recv: libloading::Symbol<
            unsafe extern "system" fn(
                HANDLE,
                *mut c_void,
                u32,
                *mut u32,
                *mut WindivertAddress,
            ) -> i32,
        > = unsafe {
            lib.get(b"WinDivertRecv\0")
                .map_err(|e| format!("Failed to get WinDivertRecv: {}", e))?
        };

        let mut len: u32 = 0;

        let result = unsafe {
            recv(
                handle,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut len,
                addr,
            )
        };

        if result == 0 {
            Err("WinDivertRecv failed".to_string())
        } else {
            Ok(len)
        }
    }

    pub fn send(&self, handle: HANDLE, buf: &[u8], addr: &WindivertAddress) -> Result<(), String> {
        let lib = self.handle.as_ref().ok_or("Library not loaded")?;

        let send: libloading::Symbol<
            unsafe extern "system" fn(HANDLE, *const c_void, u32, *const WindivertAddress) -> i32,
        > = unsafe {
            lib.get(b"WinDivertSend\0")
                .map_err(|e| format!("Failed to get WinDivertSend: {}", e))?
        };

        let result = unsafe {
            send(
                handle,
                buf.as_ptr() as *const c_void,
                buf.len() as u32,
                addr,
            )
        };

        if result == 0 {
            Err("WinDivertSend failed".to_string())
        } else {
            Ok(())
        }
    }

    pub fn close(&mut self, handle: HANDLE) -> Result<(), String> {
        if let Some(lib) = &self.handle {
            let close: libloading::Symbol<unsafe extern "system" fn(HANDLE) -> i32> = unsafe {
                lib.get(b"WinDivertClose\0")
                    .map_err(|e| format!("Failed to get WinDivertClose: {}", e))?
            };

            unsafe { close(handle) };
        }

        self.handle = None;
        Ok(())
    }
}

#[cfg(not(windows))]
pub struct WinDivert;

#[cfg(not(windows))]
impl WinDivert {
    pub fn new() -> Self {
        Self
    }
    pub fn open(
        &mut self,
        _filter: &str,
        _priority: i16,
        _layer: i32,
        _flags: u64,
    ) -> Result<HANDLE, String> {
        Err("WinDivert only available on Windows".to_string())
    }
    pub fn recv(
        &self,
        _handle: HANDLE,
        _buf: &mut [u8],
        _addr: &mut WindivertAddress,
    ) -> Result<u32, String> {
        Err("WinDivert only available on Windows".to_string())
    }
    pub fn send(
        &self,
        _handle: HANDLE,
        _buf: &[u8],
        _addr: &WindivertAddress,
    ) -> Result<(), String> {
        Err("WinDivert only available on Windows".to_string())
    }
    pub fn close(&mut self, _handle: HANDLE) -> Result<(), String> {
        Err("WinDivert only available on Windows".to_string())
    }
}
