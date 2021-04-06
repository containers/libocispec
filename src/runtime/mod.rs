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
    annotations: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "hooks")]
    hooks: Option<Hooks>,

    #[serde(rename = "hostname")]
    hostname: Option<String>,

    /// Linux platform-specific configurations
    #[serde(rename = "linux")]
    linux: Option<Linux>,

    #[serde(rename = "mounts")]
    mounts: Option<Vec<Mount>>,

    /// The version of Open Container Initiative Runtime Specification that the document complies
    /// with
    #[serde(rename = "ociVersion")]
    oci_version: String,

    #[serde(rename = "process")]
    process: Option<Process>,

    /// Configures the container's root filesystem.
    #[serde(rename = "root")]
    root: Option<Root>,

    /// Solaris platform-specific configurations
    #[serde(rename = "solaris")]
    solaris: Option<Solaris>,

    /// configuration for virtual-machine-based containers
    #[serde(rename = "vm")]
    vm: Option<Vm>,

    /// Windows platform-specific configurations
    #[serde(rename = "windows")]
    windows: Option<Windows>,
}

#[derive(Serialize, Deserialize)]
pub struct Hooks {
    #[serde(rename = "createContainer")]
    create_container: Option<Vec<CreateContainer>>,

    #[serde(rename = "createRuntime")]
    create_runtime: Option<Vec<CreateRuntime>>,

    #[serde(rename = "poststart")]
    poststart: Option<Vec<Poststart>>,

    #[serde(rename = "poststop")]
    poststop: Option<Vec<Poststop>>,

    #[serde(rename = "prestart")]
    prestart: Option<Vec<Prestart>>,

    #[serde(rename = "startContainer")]
    start_container: Option<Vec<StartContainer>>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateContainer {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRuntime {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Poststart {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Poststop {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Prestart {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct StartContainer {
    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "timeout")]
    timeout: Option<i64>,
}

/// Linux platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Linux {
    #[serde(rename = "cgroupsPath")]
    cgroups_path: Option<String>,

    #[serde(rename = "devices")]
    devices: Option<Vec<LinuxDevice>>,

    #[serde(rename = "gidMappings")]
    gid_mappings: Option<Vec<GidMapping>>,

    #[serde(rename = "intelRdt")]
    intel_rdt: Option<IntelRdt>,

    #[serde(rename = "maskedPaths")]
    masked_paths: Option<Vec<String>>,

    #[serde(rename = "mountLabel")]
    mount_label: Option<String>,

    #[serde(rename = "namespaces")]
    namespaces: Option<Vec<Namespace>>,

    #[serde(rename = "personality")]
    personality: Option<Personality>,

    #[serde(rename = "readonlyPaths")]
    readonly_paths: Option<Vec<String>>,

    #[serde(rename = "resources")]
    resources: Option<LinuxResources>,

    #[serde(rename = "rootfsPropagation")]
    rootfs_propagation: Option<RootfsPropagation>,

    #[serde(rename = "seccomp")]
    seccomp: Option<Seccomp>,

    #[serde(rename = "sysctl")]
    sysctl: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "uidMappings")]
    uid_mappings: Option<Vec<UidMapping>>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxDevice {
    /// File permissions mode (typically an octal value)
    #[serde(rename = "fileMode")]
    file_mode: Option<i64>,

    #[serde(rename = "gid")]
    gid: Option<i64>,

    /// major device number
    #[serde(rename = "major")]
    major: Option<i64>,

    /// minor device number
    #[serde(rename = "minor")]
    minor: Option<i64>,

    #[serde(rename = "path")]
    path: String,

    /// Type of a block or special character device
    #[serde(rename = "type")]
    device_type: String,

    #[serde(rename = "uid")]
    uid: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct GidMapping {
    #[serde(rename = "containerID")]
    container_id: i64,

    #[serde(rename = "hostID")]
    host_id: i64,

    #[serde(rename = "size")]
    size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct IntelRdt {
    #[serde(rename = "closID")]
    clos_id: Option<String>,

    #[serde(rename = "l3CacheSchema")]
    l3_cache_schema: Option<String>,

    #[serde(rename = "memBwSchema")]
    mem_bw_schema: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Namespace {
    #[serde(rename = "path")]
    path: Option<String>,

    #[serde(rename = "type")]
    namespace_type: Type,
}

#[derive(Serialize, Deserialize)]
pub struct Personality {
    #[serde(rename = "domain")]
    domain: Option<Domain>,

    #[serde(rename = "flags")]
    flags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxResources {
    #[serde(rename = "blockIO")]
    block_io: Option<BlockIo>,

    #[serde(rename = "cpu")]
    cpu: Option<PurpleCpu>,

    #[serde(rename = "devices")]
    devices: Option<Vec<ResourcesDevice>>,

    #[serde(rename = "hugepageLimits")]
    hugepage_limits: Option<Vec<HugepageLimit>>,

    #[serde(rename = "memory")]
    memory: Option<PurpleMemory>,

    #[serde(rename = "network")]
    network: Option<ResourcesNetwork>,

    #[serde(rename = "pids")]
    pids: Option<Pids>,

    #[serde(rename = "rdma")]
    rdma: Option<HashMap<String, Rdma>>,

    #[serde(rename = "unified")]
    unified: Option<HashMap<String, Option<serde_json::Value>>>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockIo {
    #[serde(rename = "leafWeight")]
    leaf_weight: Option<i64>,

    #[serde(rename = "throttleReadBpsDevice")]
    throttle_read_bps_device: Option<Vec<ThrottleReadBpsDevice>>,

    #[serde(rename = "throttleReadIOPSDevice")]
    throttle_read_iops_device: Option<Vec<ThrottleReadIopsDevice>>,

    #[serde(rename = "throttleWriteBpsDevice")]
    throttle_write_bps_device: Option<Vec<ThrottleWriteBpsDevice>>,

    #[serde(rename = "throttleWriteIOPSDevice")]
    throttle_write_iops_device: Option<Vec<ThrottleWriteIopsDevice>>,

    #[serde(rename = "weight")]
    weight: Option<i64>,

    #[serde(rename = "weightDevice")]
    weight_device: Option<Vec<WeightDevice>>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleReadBpsDevice {
    /// major device number
    #[serde(rename = "major")]
    major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    minor: i64,

    #[serde(rename = "rate")]
    rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleReadIopsDevice {
    /// major device number
    #[serde(rename = "major")]
    major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    minor: i64,

    #[serde(rename = "rate")]
    rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleWriteBpsDevice {
    /// major device number
    #[serde(rename = "major")]
    major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    minor: i64,

    #[serde(rename = "rate")]
    rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ThrottleWriteIopsDevice {
    /// major device number
    #[serde(rename = "major")]
    major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    minor: i64,

    #[serde(rename = "rate")]
    rate: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct WeightDevice {
    /// major device number
    #[serde(rename = "major")]
    major: i64,

    /// minor device number
    #[serde(rename = "minor")]
    minor: i64,

    #[serde(rename = "leafWeight")]
    leaf_weight: Option<i64>,

    #[serde(rename = "weight")]
    weight: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct PurpleCpu {
    #[serde(rename = "cpus")]
    cpus: Option<String>,

    #[serde(rename = "mems")]
    mems: Option<String>,

    #[serde(rename = "period")]
    period: Option<i64>,

    #[serde(rename = "quota")]
    quota: Option<i64>,

    #[serde(rename = "realtimePeriod")]
    realtime_period: Option<i64>,

    #[serde(rename = "realtimeRuntime")]
    realtime_runtime: Option<i64>,

    #[serde(rename = "shares")]
    shares: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct ResourcesDevice {
    #[serde(rename = "access")]
    access: Option<String>,

    #[serde(rename = "allow")]
    allow: bool,

    /// major device number
    #[serde(rename = "major")]
    major: Option<i64>,

    /// minor device number
    #[serde(rename = "minor")]
    minor: Option<i64>,

    #[serde(rename = "type")]
    device_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HugepageLimit {
    #[serde(rename = "limit")]
    limit: i64,

    #[serde(rename = "pageSize")]
    page_size: String,
}

#[derive(Serialize, Deserialize)]
pub struct PurpleMemory {
    #[serde(rename = "disableOOMKiller")]
    disable_oom_killer: Option<bool>,

    #[serde(rename = "kernel")]
    kernel: Option<i64>,

    #[serde(rename = "kernelTCP")]
    kernel_tcp: Option<i64>,

    #[serde(rename = "limit")]
    limit: Option<i64>,

    #[serde(rename = "reservation")]
    reservation: Option<i64>,

    #[serde(rename = "swap")]
    swap: Option<i64>,

    #[serde(rename = "swappiness")]
    swappiness: Option<i64>,

    #[serde(rename = "useHierarchy")]
    use_hierarchy: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ResourcesNetwork {
    #[serde(rename = "classID")]
    class_id: Option<i64>,

    #[serde(rename = "priorities")]
    priorities: Option<Vec<Priority>>,
}

#[derive(Serialize, Deserialize)]
pub struct Priority {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "priority")]
    priority: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Pids {
    #[serde(rename = "limit")]
    limit: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Rdma {
    #[serde(rename = "hcaHandles")]
    hca_handles: Option<i64>,

    #[serde(rename = "hcaObjects")]
    hca_objects: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Seccomp {
    #[serde(rename = "architectures")]
    architectures: Option<Vec<Architecture>>,

    #[serde(rename = "defaultAction")]
    default_action: Action,

    #[serde(rename = "defaultErrnoRet")]
    default_errno_ret: Option<i64>,

    #[serde(rename = "flags")]
    flags: Option<Vec<Flag>>,

    #[serde(rename = "listenerMetadata")]
    listener_metadata: Option<String>,

    #[serde(rename = "listenerPath")]
    listener_path: Option<String>,

    #[serde(rename = "syscalls")]
    syscalls: Option<Vec<Syscall>>,
}

#[derive(Serialize, Deserialize)]
pub struct Syscall {
    #[serde(rename = "action")]
    action: Action,

    #[serde(rename = "args")]
    args: Option<Vec<Arg>>,

    #[serde(rename = "errnoRet")]
    errno_ret: Option<i64>,

    #[serde(rename = "names")]
    names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Arg {
    #[serde(rename = "index")]
    index: i64,

    #[serde(rename = "op")]
    op: Op,

    #[serde(rename = "value")]
    value: i64,

    #[serde(rename = "valueTwo")]
    value_two: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct UidMapping {
    #[serde(rename = "containerID")]
    container_id: i64,

    #[serde(rename = "hostID")]
    host_id: i64,

    #[serde(rename = "size")]
    size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Mount {
    #[serde(rename = "destination")]
    destination: String,

    #[serde(rename = "options")]
    options: Option<Vec<String>>,

    #[serde(rename = "source")]
    source: Option<String>,

    #[serde(rename = "type")]
    mount_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Process {
    #[serde(rename = "apparmorProfile")]
    apparmor_profile: Option<String>,

    #[serde(rename = "args")]
    args: Option<Vec<String>>,

    #[serde(rename = "capabilities")]
    capabilities: Option<Capabilities>,

    #[serde(rename = "commandLine")]
    command_line: Option<String>,

    #[serde(rename = "consoleSize")]
    console_size: Option<ConsoleSize>,

    #[serde(rename = "cwd")]
    cwd: String,

    #[serde(rename = "env")]
    env: Option<Vec<String>>,

    #[serde(rename = "noNewPrivileges")]
    no_new_privileges: Option<bool>,

    #[serde(rename = "oomScoreAdj")]
    oom_score_adj: Option<i64>,

    #[serde(rename = "rlimits")]
    rlimits: Option<Vec<Rlimit>>,

    #[serde(rename = "selinuxLabel")]
    selinux_label: Option<String>,

    #[serde(rename = "terminal")]
    terminal: Option<bool>,

    #[serde(rename = "user")]
    user: Option<User>,
}

#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(rename = "ambient")]
    ambient: Option<Vec<String>>,

    #[serde(rename = "bounding")]
    bounding: Option<Vec<String>>,

    #[serde(rename = "effective")]
    effective: Option<Vec<String>>,

    #[serde(rename = "inheritable")]
    inheritable: Option<Vec<String>>,

    #[serde(rename = "permitted")]
    permitted: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct ConsoleSize {
    #[serde(rename = "height")]
    height: i64,

    #[serde(rename = "width")]
    width: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Rlimit {
    #[serde(rename = "hard")]
    hard: i64,

    #[serde(rename = "soft")]
    soft: i64,

    #[serde(rename = "type")]
    rlimit_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "additionalGids")]
    additional_gids: Option<Vec<i64>>,

    #[serde(rename = "gid")]
    gid: Option<i64>,

    #[serde(rename = "uid")]
    uid: Option<i64>,

    #[serde(rename = "umask")]
    umask: Option<i64>,

    #[serde(rename = "username")]
    username: Option<String>,
}

/// Configures the container's root filesystem.
#[derive(Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "readonly")]
    readonly: Option<bool>,
}

/// Solaris platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Solaris {
    #[serde(rename = "anet")]
    anet: Option<Vec<Anet>>,

    #[serde(rename = "cappedCPU")]
    capped_cpu: Option<CappedCpu>,

    #[serde(rename = "cappedMemory")]
    capped_memory: Option<CappedMemory>,

    #[serde(rename = "limitpriv")]
    limitpriv: Option<String>,

    #[serde(rename = "maxShmMemory")]
    max_shm_memory: Option<String>,

    #[serde(rename = "milestone")]
    milestone: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Anet {
    #[serde(rename = "allowedAddress")]
    allowed_address: Option<String>,

    #[serde(rename = "configureAllowedAddress")]
    configure_allowed_address: Option<String>,

    #[serde(rename = "defrouter")]
    defrouter: Option<String>,

    #[serde(rename = "linkname")]
    linkname: Option<String>,

    #[serde(rename = "linkProtection")]
    link_protection: Option<String>,

    #[serde(rename = "lowerLink")]
    lower_link: Option<String>,

    #[serde(rename = "macAddress")]
    mac_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CappedCpu {
    #[serde(rename = "ncpus")]
    ncpus: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CappedMemory {
    #[serde(rename = "physical")]
    physical: Option<String>,

    #[serde(rename = "swap")]
    swap: Option<String>,
}

/// configuration for virtual-machine-based containers
#[derive(Serialize, Deserialize)]
pub struct Vm {
    /// hypervisor config used by VM-based containers
    #[serde(rename = "hypervisor")]
    hypervisor: Option<Hypervisor>,

    /// root image config used by VM-based containers
    #[serde(rename = "image")]
    image: Option<Image>,

    /// kernel config used by VM-based containers
    #[serde(rename = "kernel")]
    kernel: Kernel,
}

/// hypervisor config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Hypervisor {
    #[serde(rename = "parameters")]
    parameters: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,
}

/// root image config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Image {
    #[serde(rename = "format")]
    format: Format,

    #[serde(rename = "path")]
    path: String,
}

/// kernel config used by VM-based containers
#[derive(Serialize, Deserialize)]
pub struct Kernel {
    #[serde(rename = "initrd")]
    initrd: Option<String>,

    #[serde(rename = "parameters")]
    parameters: Option<Vec<String>>,

    #[serde(rename = "path")]
    path: String,
}

/// Windows platform-specific configurations
#[derive(Serialize, Deserialize)]
pub struct Windows {
    #[serde(rename = "credentialSpec")]
    credential_spec: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "devices")]
    devices: Option<Vec<WindowsDevice>>,

    #[serde(rename = "hyperv")]
    hyperv: Option<Hyperv>,

    #[serde(rename = "ignoreFlushesDuringBoot")]
    ignore_flushes_during_boot: Option<bool>,

    #[serde(rename = "layerFolders")]
    layer_folders: Vec<String>,

    #[serde(rename = "network")]
    network: Option<WindowsNetwork>,

    #[serde(rename = "resources")]
    resources: Option<WindowsResources>,

    #[serde(rename = "servicing")]
    servicing: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsDevice {
    #[serde(rename = "id")]
    id: String,

    #[serde(rename = "idType")]
    id_type: IdType,
}

#[derive(Serialize, Deserialize)]
pub struct Hyperv {
    #[serde(rename = "utilityVMPath")]
    utility_vm_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsNetwork {
    #[serde(rename = "allowUnqualifiedDNSQuery")]
    allow_unqualified_dns_query: Option<bool>,

    #[serde(rename = "DNSSearchList")]
    dns_search_list: Option<Vec<String>>,

    #[serde(rename = "endpointList")]
    endpoint_list: Option<Vec<String>>,

    #[serde(rename = "networkNamespace")]
    network_namespace: Option<String>,

    #[serde(rename = "networkSharedContainerName")]
    network_shared_container_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WindowsResources {
    #[serde(rename = "cpu")]
    cpu: Option<FluffyCpu>,

    #[serde(rename = "memory")]
    memory: Option<FluffyMemory>,

    #[serde(rename = "storage")]
    storage: Option<Storage>,
}

#[derive(Serialize, Deserialize)]
pub struct FluffyCpu {
    #[serde(rename = "count")]
    count: Option<i64>,

    #[serde(rename = "maximum")]
    maximum: Option<i64>,

    #[serde(rename = "shares")]
    shares: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct FluffyMemory {
    #[serde(rename = "limit")]
    limit: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Storage {
    #[serde(rename = "bps")]
    bps: Option<i64>,

    #[serde(rename = "iops")]
    iops: Option<i64>,

    #[serde(rename = "sandboxSize")]
    sandbox_size: Option<i64>,
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
