// Example code that deserializes and serializes the model.
// extern crate serde;
// #[macro_use]
// extern crate serde_derive;
// extern crate serde_json;
//
// use generated_module::[object Object];
//
// fn main() {
//     let json = r#"{"answer": 42}"#;
//     let model: [object Object] = serde_json::from_str(&json).unwrap();
// }

extern crate serde_derive;
use std::collections::HashMap;

/// Open Container Initiative Runtime Specification Container Configuration Schema
#[derive(Serialize, Deserialize)]
pub struct Spec {
    #[serde(rename = "annotations")]
    pub annotations: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "hooks")]
    pub hooks: Option<Hooks>,

    #[serde(rename = "hostname")]
    pub hostname: Option<String>,

    /// Linux platform-specific configurations
    #[serde(rename = "linux")]
    pub linux: Option<Linux>,

    #[serde(rename = "mounts")]
    pub mounts: Option<Vec<Mount>>,

    /// The version of Open Container Initiative Runtime Specification that the document complies
    /// with
    #[serde(rename = "ociVersion")]
    pub oci_version: String,

    #[serde(rename = "process")]
    pub process: Option<Process>,

    /// Configures the container's root filesystem.
    #[serde(rename = "root")]
    pub root: Option<Root>,

    /// Solaris platform-specific configurations
    #[serde(rename = "solaris")]
    pub solaris: Option<Solaris>,

    /// configuration for virtual-machine-based containers
    #[serde(rename = "vm")]
    pub vm: Option<Vm>,

    /// Windows platform-specific configurations
    #[serde(rename = "windows")]
    pub windows: Option<Windows>,

    /// z/OS platform-specific configurations
    #[serde(rename = "zos")]
    pub zos: Option<Zos>,
}

#[derive(Serialize, Deserialize)]
pub struct Hooks {
    #[serde(rename = "createContainer")]
    pub create_container: Option<Vec<CreateContainer>>,

    #[serde(rename = "createRuntime")]
    pub create_runtime: Option<Vec<CreateRuntime>>,

    #[serde(rename = "poststart")]
    pub poststart: Option<Vec<Poststart>>,

    #[serde(rename = "poststop")]
    pub poststop: Option<Vec<Poststop>>,

    #[serde(rename = "prestart")]
    pub prestart: Option<Vec<Prestart>>,

    #[serde(rename = "startContainer")]
    pub start_container: Option<Vec<StartContainer>>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateContainer {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRuntime {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Poststart {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Poststop {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Prestart {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct StartContainer {
    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "timeout")]
    pub timeout: Option<i64>,
}

/// Linux platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Linux {
    #[serde(rename = "cgroupsPath")]
    pub cgroups_path: Option<String>,

    #[serde(rename = "devices")]
    pub devices: Option<Vec<LinuxDevice>>,

    #[serde(rename = "gidMappings")]
    pub gid_mappings: Option<Vec<LinuxGidMapping>>,

    #[serde(rename = "intelRdt")]
    pub intel_rdt: Option<IntelRdt>,

    #[serde(rename = "maskedPaths")]
    pub masked_paths: Option<Vec<String>>,

    #[serde(rename = "mountLabel")]
    pub mount_label: Option<String>,

    #[serde(rename = "namespaces")]
    pub namespaces: Option<Vec<Namespace>>,

    #[serde(rename = "personality")]
    pub personality: Option<Personality>,

    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Option<Vec<String>>,

    #[serde(rename = "resources")]
    pub resources: Option<LinuxResources>,

    #[serde(rename = "rootfsPropagation")]
    pub rootfs_propagation: Option<RootfsPropagation>,

    #[serde(rename = "seccomp")]
    pub seccomp: Option<Seccomp>,

    #[serde(rename = "sysctl")]
    pub sysctl: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "uidMappings")]
    pub uid_mappings: Option<Vec<LinuxUidMapping>>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxDevice {
    /// File permissions mode (typically an octal value)
    #[serde(rename = "fileMode")]
    pub file_mode: Option<i64>,

    #[serde(rename = "gid")]
    pub gid: Option<i64>,

    /// major device number
    #[serde(rename = "major")]
    pub major: Option<i64>,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: Option<i64>,

    #[serde(rename = "path")]
    pub path: String,

    /// Type of a block or special character device
    #[serde(rename = "type")]
    pub device_type: String,

    #[serde(rename = "uid")]
    pub uid: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxGidMapping {
    #[serde(rename = "containerID")]
    pub container_id: i64,

    #[serde(rename = "hostID")]
    pub host_id: i64,

    #[serde(rename = "size")]
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct IntelRdt {
    #[serde(rename = "closID")]
    pub clos_id: Option<String>,

    #[serde(rename = "enableCMT")]
    pub enable_cmt: Option<bool>,

    #[serde(rename = "enableMBM")]
    pub enable_mbm: Option<bool>,

    #[serde(rename = "l3CacheSchema")]
    pub l3_cache_schema: Option<String>,

    #[serde(rename = "memBwSchema")]
    pub mem_bw_schema: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Namespace {
    #[serde(rename = "path")]
    pub path: Option<String>,

    #[serde(rename = "type")]
    pub namespace_type: Type,
}

#[derive(Serialize, Deserialize)]
pub struct Personality {
    #[serde(rename = "domain")]
    pub domain: Option<Domain>,

    #[serde(rename = "flags")]
    pub flags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxResources {
    #[serde(rename = "blockIO")]
    pub block_io: Option<BlockIo>,

    #[serde(rename = "cpu")]
    pub cpu: Option<PurpleCpu>,

    #[serde(rename = "devices")]
    pub devices: Option<Vec<ResourcesDevice>>,

    #[serde(rename = "hugepageLimits")]
    pub hugepage_limits: Option<Vec<HugepageLimit>>,

    #[serde(rename = "memory")]
    pub memory: Option<PurpleMemory>,

    #[serde(rename = "network")]
    pub network: Option<ResourcesNetwork>,

    #[serde(rename = "pids")]
    pub pids: Option<Pids>,

    #[serde(rename = "rdma")]
    pub rdma: Option<HashMap<String, Rdma>>,

    #[serde(rename = "unified")]
    pub unified: Option<HashMap<String, Option<serde_json::Value>>>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockIo {
    #[serde(rename = "leafWeight")]
    pub leaf_weight: Option<i64>,

    #[serde(rename = "throttleReadBpsDevice")]
    pub throttle_read_bps_device: Option<Vec<ThrottleReadBpsDevice>>,

    #[serde(rename = "throttleReadIOPSDevice")]
    pub throttle_read_iops_device: Option<Vec<ThrottleReadIopsDevice>>,

    #[serde(rename = "throttleWriteBpsDevice")]
    pub throttle_write_bps_device: Option<Vec<ThrottleWriteBpsDevice>>,

    #[serde(rename = "throttleWriteIOPSDevice")]
    pub throttle_write_iops_device: Option<Vec<ThrottleWriteIopsDevice>>,

    #[serde(rename = "weight")]
    pub weight: Option<i64>,

    #[serde(rename = "weightDevice")]
    pub weight_device: Option<Vec<WeightDevice>>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleReadBpsDevice {
    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "rate")]
    pub rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleReadIopsDevice {
    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "rate")]
    pub rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleWriteBpsDevice {
    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "rate")]
    pub rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleWriteIopsDevice {
    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "rate")]
    pub rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct WeightDevice {
    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "leafWeight")]
    pub leaf_weight: Option<i64>,

    #[serde(rename = "weight")]
    pub weight: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct PurpleCpu {
    #[serde(rename = "cpus")]
    pub cpus: Option<String>,

    #[serde(rename = "idle")]
    pub idle: Option<i64>,

    #[serde(rename = "mems")]
    pub mems: Option<String>,

    #[serde(rename = "period")]
    pub period: Option<i64>,

    #[serde(rename = "quota")]
    pub quota: Option<i64>,

    #[serde(rename = "realtimePeriod")]
    pub realtime_period: Option<i64>,

    #[serde(rename = "realtimeRuntime")]
    pub realtime_runtime: Option<i64>,

    #[serde(rename = "shares")]
    pub shares: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ResourcesDevice {
    #[serde(rename = "access")]
    pub access: Option<String>,

    #[serde(rename = "allow")]
    pub allow: bool,

    /// major device number
    #[serde(rename = "major")]
    pub major: Option<i64>,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: Option<i64>,

    #[serde(rename = "type")]
    pub device_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HugepageLimit {
    #[serde(rename = "limit")]
    pub limit: i64,

    #[serde(rename = "pageSize")]
    pub page_size: String,
}

#[derive(Serialize, Deserialize)]
pub struct PurpleMemory {
    #[serde(rename = "disableOOMKiller")]
    pub disable_oom_killer: Option<bool>,

    #[serde(rename = "kernel")]
    pub kernel: Option<i64>,

    #[serde(rename = "kernelTCP")]
    pub kernel_tcp: Option<i64>,

    #[serde(rename = "limit")]
    pub limit: Option<i64>,

    #[serde(rename = "reservation")]
    pub reservation: Option<i64>,

    #[serde(rename = "swap")]
    pub swap: Option<i64>,

    #[serde(rename = "swappiness")]
    pub swappiness: Option<i64>,

    #[serde(rename = "useHierarchy")]
    pub use_hierarchy: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ResourcesNetwork {
    #[serde(rename = "classID")]
    pub class_id: Option<i64>,

    #[serde(rename = "priorities")]
    pub priorities: Option<Vec<Priority>>,
}

#[derive(Serialize, Deserialize)]
pub struct Priority {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "priority")]
    pub priority: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Pids {
    #[serde(rename = "limit")]
    pub limit: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Rdma {
    #[serde(rename = "hcaHandles")]
    pub hca_handles: Option<i64>,

    #[serde(rename = "hcaObjects")]
    pub hca_objects: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Seccomp {
    #[serde(rename = "architectures")]
    pub architectures: Option<Vec<Architecture>>,

    #[serde(rename = "defaultAction")]
    pub default_action: Action,

    #[serde(rename = "defaultErrnoRet")]
    pub default_errno_ret: Option<i64>,

    #[serde(rename = "flags")]
    pub flags: Option<Vec<Flag>>,

    #[serde(rename = "listenerMetadata")]
    pub listener_metadata: Option<String>,

    #[serde(rename = "listenerPath")]
    pub listener_path: Option<String>,

    #[serde(rename = "syscalls")]
    pub syscalls: Option<Vec<Syscall>>,
}

#[derive(Serialize, Deserialize)]
pub struct Syscall {
    #[serde(rename = "action")]
    pub action: Action,

    #[serde(rename = "args")]
    pub args: Option<Vec<Arg>>,

    #[serde(rename = "errnoRet")]
    pub errno_ret: Option<i64>,

    #[serde(rename = "names")]
    pub names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Arg {
    #[serde(rename = "index")]
    pub index: i64,

    #[serde(rename = "op")]
    pub op: Op,

    #[serde(rename = "value")]
    pub value: i64,

    #[serde(rename = "valueTwo")]
    pub value_two: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxUidMapping {
    #[serde(rename = "containerID")]
    pub container_id: i64,

    #[serde(rename = "hostID")]
    pub host_id: i64,

    #[serde(rename = "size")]
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Mount {
    #[serde(rename = "destination")]
    pub destination: String,

    #[serde(rename = "gidMappings")]
    pub gid_mappings: Option<Vec<MountGidMapping>>,

    #[serde(rename = "options")]
    pub options: Option<Vec<String>>,

    #[serde(rename = "source")]
    pub source: Option<String>,

    #[serde(rename = "type")]
    pub mount_type: Option<String>,

    #[serde(rename = "uidMappings")]
    pub uid_mappings: Option<Vec<MountUidMapping>>,
}

#[derive(Serialize, Deserialize)]
pub struct MountGidMapping {
    #[serde(rename = "containerID")]
    pub container_id: i64,

    #[serde(rename = "hostID")]
    pub host_id: i64,

    #[serde(rename = "size")]
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct MountUidMapping {
    #[serde(rename = "containerID")]
    pub container_id: i64,

    #[serde(rename = "hostID")]
    pub host_id: i64,

    #[serde(rename = "size")]
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Process {
    #[serde(rename = "apparmorProfile")]
    pub apparmor_profile: Option<String>,

    #[serde(rename = "args")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "capabilities")]
    pub capabilities: Option<Capabilities>,

    #[serde(rename = "commandLine")]
    pub command_line: Option<String>,

    #[serde(rename = "consoleSize")]
    pub console_size: Option<ConsoleSize>,

    #[serde(rename = "cwd")]
    pub cwd: String,

    #[serde(rename = "env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: Option<bool>,

    #[serde(rename = "oomScoreAdj")]
    pub oom_score_adj: Option<i64>,

    #[serde(rename = "rlimits")]
    pub rlimits: Option<Vec<Rlimit>>,

    #[serde(rename = "selinuxLabel")]
    pub selinux_label: Option<String>,

    #[serde(rename = "terminal")]
    pub terminal: Option<bool>,

    #[serde(rename = "user")]
    pub user: Option<User>,
}

#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(rename = "ambient")]
    pub ambient: Option<Vec<String>>,

    #[serde(rename = "bounding")]
    pub bounding: Option<Vec<String>>,

    #[serde(rename = "effective")]
    pub effective: Option<Vec<String>>,

    #[serde(rename = "inheritable")]
    pub inheritable: Option<Vec<String>>,

    #[serde(rename = "permitted")]
    pub permitted: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct ConsoleSize {
    #[serde(rename = "height")]
    pub height: i64,

    #[serde(rename = "width")]
    pub width: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Rlimit {
    #[serde(rename = "hard")]
    pub hard: i64,

    #[serde(rename = "soft")]
    pub soft: i64,

    #[serde(rename = "type")]
    pub rlimit_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "additionalGids")]
    pub additional_gids: Option<Vec<i64>>,

    #[serde(rename = "gid")]
    pub gid: Option<i64>,

    #[serde(rename = "uid")]
    pub uid: Option<i64>,

    #[serde(rename = "umask")]
    pub umask: Option<i64>,

    #[serde(rename = "username")]
    pub username: Option<String>,
}

/// Configures the container's root filesystem.
#[derive(Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "readonly")]
    pub readonly: Option<bool>,
}

/// Solaris platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Solaris {
    #[serde(rename = "anet")]
    pub anet: Option<Vec<Anet>>,

    #[serde(rename = "cappedCPU")]
    pub capped_cpu: Option<CappedCpu>,

    #[serde(rename = "cappedMemory")]
    pub capped_memory: Option<CappedMemory>,

    #[serde(rename = "limitpriv")]
    pub limitpriv: Option<String>,

    #[serde(rename = "maxShmMemory")]
    pub max_shm_memory: Option<String>,

    #[serde(rename = "milestone")]
    pub milestone: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Anet {
    #[serde(rename = "allowedAddress")]
    pub allowed_address: Option<String>,

    #[serde(rename = "configureAllowedAddress")]
    pub configure_allowed_address: Option<String>,

    #[serde(rename = "defrouter")]
    pub defrouter: Option<String>,

    #[serde(rename = "linkname")]
    pub linkname: Option<String>,

    #[serde(rename = "linkProtection")]
    pub link_protection: Option<String>,

    #[serde(rename = "lowerLink")]
    pub lower_link: Option<String>,

    #[serde(rename = "macAddress")]
    pub mac_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CappedCpu {
    #[serde(rename = "ncpus")]
    pub ncpus: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CappedMemory {
    #[serde(rename = "physical")]
    pub physical: Option<String>,

    #[serde(rename = "swap")]
    pub swap: Option<String>,
}

/// configuration for virtual-machine-based containers
#[derive(Serialize, Deserialize)]
pub struct Vm {
    /// hypervisor config used by VM-based containers
    #[serde(rename = "hypervisor")]
    pub hypervisor: Option<Hypervisor>,

    /// root image config used by VM-based containers
    #[serde(rename = "image")]
    pub image: Option<Image>,

    /// kernel config used by VM-based containers
    #[serde(rename = "kernel")]
    pub kernel: Kernel,
}

/// hypervisor config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Hypervisor {
    #[serde(rename = "parameters")]
    pub parameters: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,
}

/// root image config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Image {
    #[serde(rename = "format")]
    pub format: Format,

    #[serde(rename = "path")]
    pub path: String,
}

/// kernel config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Kernel {
    #[serde(rename = "initrd")]
    pub initrd: Option<String>,

    #[serde(rename = "parameters")]
    pub parameters: Option<Vec<String>>,

    #[serde(rename = "path")]
    pub path: String,
}

/// Windows platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Windows {
    #[serde(rename = "credentialSpec")]
    pub credential_spec: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "devices")]
    pub devices: Option<Vec<WindowsDevice>>,

    #[serde(rename = "hyperv")]
    pub hyperv: Option<Hyperv>,

    #[serde(rename = "ignoreFlushesDuringBoot")]
    pub ignore_flushes_during_boot: Option<bool>,

    #[serde(rename = "layerFolders")]
    pub layer_folders: Vec<String>,

    #[serde(rename = "network")]
    pub network: Option<WindowsNetwork>,

    #[serde(rename = "resources")]
    pub resources: Option<WindowsResources>,

    #[serde(rename = "servicing")]
    pub servicing: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsDevice {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "idType")]
    pub id_type: IdType,
}

#[derive(Serialize, Deserialize)]
pub struct Hyperv {
    #[serde(rename = "utilityVMPath")]
    pub utility_vm_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsNetwork {
    #[serde(rename = "allowUnqualifiedDNSQuery")]
    pub allow_unqualified_dns_query: Option<bool>,

    #[serde(rename = "DNSSearchList")]
    pub dns_search_list: Option<Vec<String>>,

    #[serde(rename = "endpointList")]
    pub endpoint_list: Option<Vec<String>>,

    #[serde(rename = "networkNamespace")]
    pub network_namespace: Option<String>,

    #[serde(rename = "networkSharedContainerName")]
    pub network_shared_container_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsResources {
    #[serde(rename = "cpu")]
    pub cpu: Option<FluffyCpu>,

    #[serde(rename = "memory")]
    pub memory: Option<FluffyMemory>,

    #[serde(rename = "storage")]
    pub storage: Option<Storage>,
}

#[derive(Serialize, Deserialize)]
pub struct FluffyCpu {
    #[serde(rename = "count")]
    pub count: Option<i64>,

    #[serde(rename = "maximum")]
    pub maximum: Option<i64>,

    #[serde(rename = "shares")]
    pub shares: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct FluffyMemory {
    #[serde(rename = "limit")]
    pub limit: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Storage {
    #[serde(rename = "bps")]
    pub bps: Option<i64>,

    #[serde(rename = "iops")]
    pub iops: Option<i64>,

    #[serde(rename = "sandboxSize")]
    pub sandbox_size: Option<i64>,
}

/// z/OS platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Zos {
    #[serde(rename = "devices")]
    pub devices: Option<Vec<ZosDevice>>,
}

#[derive(Serialize, Deserialize)]
pub struct ZosDevice {
    /// File permissions mode (typically an octal value)
    #[serde(rename = "fileMode")]
    pub file_mode: Option<i64>,

    #[serde(rename = "gid")]
    pub gid: Option<i64>,

    /// major device number
    #[serde(rename = "major")]
    pub major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    pub minor: i64,

    #[serde(rename = "path")]
    pub path: String,

    /// Type of a block or special character device
    #[serde(rename = "type")]
    pub device_type: String,

    #[serde(rename = "uid")]
    pub uid: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "cgroup")]
    Cgroup,

    #[serde(rename = "ipc")]
    Ipc,

    #[serde(rename = "mount")]
    Mount,

    #[serde(rename = "network")]
    Network,

    #[serde(rename = "pid")]
    Pid,

    #[serde(rename = "user")]
    User,

    #[serde(rename = "uts")]
    Uts,
}

#[derive(Serialize, Deserialize)]
pub enum Domain {
    #[serde(rename = "LINUX")]
    Linux,

    #[serde(rename = "LINUX32")]
    Linux32,
}

#[derive(Serialize, Deserialize)]
pub enum RootfsPropagation {
    #[serde(rename = "private")]
    Private,

    #[serde(rename = "shared")]
    Shared,

    #[serde(rename = "slave")]
    Slave,

    #[serde(rename = "unbindable")]
    Unbindable,
}

#[derive(Serialize, Deserialize)]
pub enum Architecture {
    #[serde(rename = "SCMP_ARCH_AARCH64")]
    ScmpArchAarch64,

    #[serde(rename = "SCMP_ARCH_ARM")]
    ScmpArchArm,

    #[serde(rename = "SCMP_ARCH_MIPS")]
    ScmpArchMips,

    #[serde(rename = "SCMP_ARCH_MIPS64")]
    ScmpArchMips64,

    #[serde(rename = "SCMP_ARCH_MIPS64N32")]
    ScmpArchMips64N32,

    #[serde(rename = "SCMP_ARCH_MIPSEL")]
    ScmpArchMipsel,

    #[serde(rename = "SCMP_ARCH_MIPSEL64")]
    ScmpArchMipsel64,

    #[serde(rename = "SCMP_ARCH_MIPSEL64N32")]
    ScmpArchMipsel64N32,

    #[serde(rename = "SCMP_ARCH_PARISC")]
    ScmpArchParisc,

    #[serde(rename = "SCMP_ARCH_PARISC64")]
    ScmpArchParisc64,

    #[serde(rename = "SCMP_ARCH_PPC")]
    ScmpArchPpc,

    #[serde(rename = "SCMP_ARCH_PPC64")]
    ScmpArchPpc64,

    #[serde(rename = "SCMP_ARCH_PPC64LE")]
    ScmpArchPpc64Le,

    #[serde(rename = "SCMP_ARCH_RISCV64")]
    ScmpArchRiscv64,

    #[serde(rename = "SCMP_ARCH_S390")]
    ScmpArchS390,

    #[serde(rename = "SCMP_ARCH_S390X")]
    ScmpArchS390X,

    #[serde(rename = "SCMP_ARCH_X32")]
    ScmpArchX32,

    #[serde(rename = "SCMP_ARCH_X86")]
    ScmpArchX86,

    #[serde(rename = "SCMP_ARCH_X86_64")]
    ScmpArchX8664,
}

#[derive(Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "SCMP_ACT_ALLOW")]
    ScmpActAllow,

    #[serde(rename = "SCMP_ACT_ERRNO")]
    ScmpActErrno,

    #[serde(rename = "SCMP_ACT_KILL")]
    ScmpActKill,

    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    ScmpActKillProcess,

    #[serde(rename = "SCMP_ACT_KILL_THREAD")]
    ScmpActKillThread,

    #[serde(rename = "SCMP_ACT_LOG")]
    ScmpActLog,

    #[serde(rename = "SCMP_ACT_NOTIFY")]
    ScmpActNotify,

    #[serde(rename = "SCMP_ACT_TRACE")]
    ScmpActTrace,

    #[serde(rename = "SCMP_ACT_TRAP")]
    ScmpActTrap,
}

#[derive(Serialize, Deserialize)]
pub enum Flag {
    #[serde(rename = "SECCOMP_FILTER_FLAG_LOG")]
    SeccompFilterFlagLog,

    #[serde(rename = "SECCOMP_FILTER_FLAG_SPEC_ALLOW")]
    SeccompFilterFlagSpecAllow,

    #[serde(rename = "SECCOMP_FILTER_FLAG_TSYNC")]
    SeccompFilterFlagTsync,
}

#[derive(Serialize, Deserialize)]
pub enum Op {
    #[serde(rename = "SCMP_CMP_EQ")]
    ScmpCmpEq,

    #[serde(rename = "SCMP_CMP_GE")]
    ScmpCmpGe,

    #[serde(rename = "SCMP_CMP_GT")]
    ScmpCmpGt,

    #[serde(rename = "SCMP_CMP_LE")]
    ScmpCmpLe,

    #[serde(rename = "SCMP_CMP_LT")]
    ScmpCmpLt,

    #[serde(rename = "SCMP_CMP_MASKED_EQ")]
    ScmpCmpMaskedEq,

    #[serde(rename = "SCMP_CMP_NE")]
    ScmpCmpNe,
}

#[derive(Serialize, Deserialize)]
pub enum Format {
    #[serde(rename = "qcow2")]
    Qcow2,

    #[serde(rename = "raw")]
    Raw,

    #[serde(rename = "vdi")]
    Vdi,

    #[serde(rename = "vhd")]
    Vhd,

    #[serde(rename = "vmdk")]
    Vmdk,
}

#[derive(Serialize, Deserialize)]
pub enum IdType {
    #[serde(rename = "class")]
    Class,
}
