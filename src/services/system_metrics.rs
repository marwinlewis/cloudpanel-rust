use serde::Serialize;
use std::collections::HashSet;
use std::time::Instant;
use sysinfo::{Disks, Networks, ProcessesToUpdate, System};

#[derive(Debug, Serialize)]
pub struct DiskMetric {
    pub name: String,
    pub mount_point: String,
    pub total_space_bytes: u64,
    pub available_space_bytes: u64,
    pub used_space_bytes: u64,
    pub usage_percentage: f32,
}

#[derive(Debug, Serialize)]
pub struct ProcessMetric {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SystemMetricsResponse {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub uptime_seconds: u64,
    pub load_average: [f64; 3],
    pub cpu_count: usize,
    pub total_cpu_usage: f32,
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub memory_usage_percentage: f32,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    pub disks: Vec<DiskMetric>,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_per_sec: u64,
    pub network_tx_per_sec: u64,
    pub top_processes: Vec<ProcessMetric>,
}

/// Long-lived collector: keeping `System` around gives accurate CPU deltas between
/// polls without sleeping and avoids re-enumerating the whole system every request.
pub struct MetricsCollector {
    sys: System,
    networks: Networks,
    disks: Disks,
    last_net_refresh: Instant,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            last_net_refresh: Instant::now(),
        }
    }
}

fn pct(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64 * 100.0) as f32
    }
}

impl MetricsCollector {
    pub fn collect(&mut self) -> SystemMetricsResponse {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.disks.refresh_list();

        let elapsed = self.last_net_refresh.elapsed().as_secs_f64().max(0.001);
        self.networks.refresh();
        self.last_net_refresh = Instant::now();

        let (mut rx_total, mut tx_total, mut rx_delta, mut tx_delta) = (0, 0, 0, 0);
        for (name, data) in &self.networks {
            if name == "lo" || name.starts_with("veth") || name.starts_with("docker") || name.starts_with("br-") {
                continue;
            }
            rx_total += data.total_received();
            tx_total += data.total_transmitted();
            rx_delta += data.received();
            tx_delta += data.transmitted();
        }

        let mut seen = HashSet::new();
        let disks = self
            .disks
            .iter()
            .filter(|d| d.total_space() > 0 && seen.insert(d.name().to_os_string()))
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                let used = total.saturating_sub(available);
                DiskMetric {
                    name: d.name().to_string_lossy().into_owned(),
                    mount_point: d.mount_point().to_string_lossy().into_owned(),
                    total_space_bytes: total,
                    available_space_bytes: available,
                    used_space_bytes: used,
                    usage_percentage: pct(used, total),
                }
            })
            .collect();

        let mut processes: Vec<ProcessMetric> = self
            .sys
            .processes()
            .iter()
            .filter(|(_, p)| p.thread_kind().is_none())
            .map(|(pid, p)| ProcessMetric {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().into_owned(),
                cpu_usage: p.cpu_usage(),
                memory_bytes: p.memory(),
            })
            .collect();
        processes.sort_by(|a, b| {
            b.cpu_usage
                .total_cmp(&a.cpu_usage)
                .then(b.memory_bytes.cmp(&a.memory_bytes))
        });
        processes.truncate(10);

        let load = System::load_average();
        let total_memory = self.sys.total_memory();
        let used_memory = self.sys.used_memory();

        SystemMetricsResponse {
            hostname: System::host_name().unwrap_or_else(|| "localhost".into()),
            os_name: System::name().unwrap_or_else(|| "Linux".into()),
            os_version: System::os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".into()),
            uptime_seconds: System::uptime(),
            load_average: [load.one, load.five, load.fifteen],
            cpu_count: self.sys.cpus().len(),
            total_cpu_usage: self.sys.global_cpu_usage(),
            total_memory_bytes: total_memory,
            used_memory_bytes: used_memory,
            memory_usage_percentage: pct(used_memory, total_memory),
            total_swap_bytes: self.sys.total_swap(),
            used_swap_bytes: self.sys.used_swap(),
            disks,
            network_rx_bytes: rx_total,
            network_tx_bytes: tx_total,
            network_rx_per_sec: (rx_delta as f64 / elapsed) as u64,
            network_tx_per_sec: (tx_delta as f64 / elapsed) as u64,
            top_processes: processes,
        }
    }
}
