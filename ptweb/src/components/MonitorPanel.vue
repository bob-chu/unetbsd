<script setup>
import { ref, watch, onMounted, onUnmounted, markRaw } from 'vue';
import { getStats } from '../api';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line } from 'vue-chartjs';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const props = defineProps({
  isActive: Boolean,
  state: String
});

const clearHistory = () => {
  labels.value = [];
  groupMetricsHistory.value = { client: {}, server: {} };
  lastTimeIndex = -1;
};

watch(() => props.state, (newState) => {
  if (newState === 'RUNNING') {
    console.log('[Monitor] Test started, clearing history');
    clearHistory();
  }
});

// History Config
const historyLength = 300; // 5 minutes at 1Hz

// State
const labels = ref([]);
// Role -> { metricKey: number[] }
const groupMetricsHistory = ref({
    'client': {},
    'server': {}
});
const availableMetrics = ref({
    'client': [],
    'server': []
});
const enabledMetrics = ref({
    'client': ['tcp_bytes_sent_mbps', 'tcp_bytes_received_mbps', 'requests_sent_rate'],
    'server': ['tcp_bytes_received_mbps', 'tcp_bytes_sent_mbps', 'http_req_rcvd_rate']
});

const showSelector = ref(null); // 'client', 'server' or null

// Formatting helpers
const formatMetricName = (name) => {
  if (name.endsWith('_mbps')) {
    return name.replace('_mbps', '').replace(/_/g, ' ').toUpperCase() + ' (Mbps)';
  }
  if (name.endsWith('_rate')) {
    return name.replace('_rate', '').replace(/_/g, ' ').toUpperCase() + ' (/s)';
  }
  return name.replace(/_/g, ' ').toUpperCase();
};

const formatMetricValue = (val, metric = '') => {
  if (typeof val !== 'number') return val;
  if (metric.endsWith('_mbps')) {
    if (val === 0) return '0.00';
    if (val < 0.001) return val.toFixed(5);
    if (val < 0.01) return val.toFixed(4);
    if (val < 0.1) return val.toFixed(3);
    return val.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  if (metric.endsWith('_rate')) {
    return val.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  return val.toLocaleString(undefined, { maximumFractionDigits: 1 });
};

const getMetricColor = (role, index) => {
  const clientColors = ['#3b82f6', '#60a5fa', '#2563eb', '#1d4ed8'];
  const serverColors = ['#10b981', '#34d399', '#059669', '#047857'];
  const colors = role === 'client' ? clientColors : serverColors;
  return colors[index % colors.length];
};

// Chart Config
const getChartOptions = (role, index) => markRaw({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  interaction: {
    intersect: false,
    mode: 'index',
  },
  scales: {
    y: {
      beginAtZero: true,
      grid: { color: '#334155', display: false },
      ticks: { 
        display: true,
        color: '#64748b',
        font: { size: 10 },
        maxTicksLimit: 3,
        callback: (value) => {
            if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
            if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
            return value;
        }
      }
    },
    x: {
      grid: { display: false },
      ticks: { 
        display: true, 
        color: '#475569', 
        font: { size: 9 },
        maxTicksLimit: 8, // More ticks for better timeline
        autoSkip: true,
        callback: (value, index, ticks) => {
            return value; // The raw time index string
        }
      }
    }
  },
  plugins: {
    legend: { display: false },
    tooltip: { 
        enabled: true,
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        titleColor: '#94a3b8',
        bodyColor: '#f1f5f9',
        borderColor: '#334155',
        borderWidth: 1,
        padding: 8,
        displayColors: false,
        callbacks: {
            title: (context) => `Time Index: ${context[0].label}`,
            label: (context) => `Value: ${formatMetricValue(context.parsed.y, context.dataset.label)}`
        }
    }
  }
});

// Polling Logic
let interval = null;
let lastTimeIndex = -1;

const fetchData = async () => {
  if (!props.isActive) return;

  try {
    const res = await getStats();
    const data = res.data;
    if (!data || !data.clients) return;

    let maxTimeIndex = -1;
    const roleTotals = { 'client': {}, 'server': {} };
    const discoveredClient = new Set(availableMetrics.value.client);
    const discoveredServer = new Set(availableMetrics.value.server);
    let newDiscovery = false;

    // 1. Discovery and Aggregation by ROLE
    for (const stats of Object.values(data.clients)) {
        const role = (stats.role || 'client').toLowerCase();
        
        for (const [key, val] of Object.entries(stats)) {
            if (typeof val === 'number') {
                if (['current_phase', 'is_dpdk_client', 'last_update', 'client_ring_idx', 'client_lcore_id', 'core_id', 'last_time_index'].includes(key)) continue;
                if (key === 'time_index') {
                    if (val > maxTimeIndex) maxTimeIndex = val;
                    continue;
                }

                roleTotals[role][key] = (roleTotals[role][key] || 0) + val;
                
                if (role === 'client') {
                    if (!discoveredClient.has(key)) {
                        discoveredClient.add(key);
                        newDiscovery = true;
                    }
                } else {
                    if (!discoveredServer.has(key)) {
                        discoveredServer.add(key);
                        newDiscovery = true;
                    }
                }
            }
        }
    }

    if (newDiscovery) {
        availableMetrics.value = {
            client: Array.from(discoveredClient).sort(),
            server: Array.from(discoveredServer).sort()
        };
    }

    // 2. Reset Handling
    if (maxTimeIndex > 0 && maxTimeIndex < lastTimeIndex - 5) {
        console.log('[Monitor] Time index regression detected, clearing history');
        clearHistory();
    }

    // 3. Time Progression Check (Strictly strictly increasing)
    if (maxTimeIndex > 0 && maxTimeIndex <= lastTimeIndex) return;
    
    // Debugging: Log high values to track scale
    if (maxTimeIndex % 10 === 0) {
        console.log(`[Monitor] Time:${maxTimeIndex}`, roleTotals);
    }

    lastTimeIndex = maxTimeIndex;

    // 4. Update History
    const newLabels = [...labels.value, maxTimeIndex.toString()];
    if (newLabels.length > historyLength) newLabels.shift();
    labels.value = newLabels;

    const newHistory = { ...groupMetricsHistory.value };
    for (const role of ['client', 'server']) {
        const roleHistory = { ...newHistory[role] };
        for (const metric of availableMetrics.value[role]) {
            if (!roleHistory[metric]) {
                roleHistory[metric] = new Array(newLabels.length - 1).fill(0);
            }
            const val = roleTotals[role][metric] || 0;
            const arr = [...roleHistory[metric], val];
            if (arr.length > historyLength) arr.shift();
            roleHistory[metric] = arr;
        }
        newHistory[role] = roleHistory;
    }
    groupMetricsHistory.value = newHistory;

  } catch (err) {
    console.error("Monitor Fetch Error:", err);
  }
};

const toggleMetric = (role, key) => {
    const idx = enabledMetrics.value[role].indexOf(key);
    if (idx > -1) {
        enabledMetrics.value[role].splice(idx, 1);
    } else {
        enabledMetrics.value[role].push(key);
    }
};

onMounted(() => {
  interval = setInterval(fetchData, 1000);
});

onUnmounted(() => {
  if (interval) clearInterval(interval);
});
</script>

<template>
  <div class="space-y-8 animate-fade-in flex flex-col h-full bg-slate-900/50 p-2 rounded-2xl">
    
    <!-- GROUP: CLIENTS -->
    <section class="space-y-4 relative" :style="{ zIndex: showSelector === 'client' ? 60 : 10 }">
        <div class="flex justify-between items-center bg-slate-800/80 backdrop-blur p-3 rounded-xl border border-slate-700 shadow-xl relative z-20">
            <div class="flex items-center gap-3 font-medium">
                <span class="text-2xl">💻</span>
                <div>
                    <h2 class="text-base font-bold text-slate-100 leading-none">Client Group Metrics</h2>
                    <p class="text-[10px] text-slate-500 uppercase font-mono mt-1">Aggregated statistics for all client nodes</p>
                </div>
            </div>

            <div class="relative">
                <button 
                    @click="showSelector = showSelector === 'client' ? null : 'client'"
                    class="px-3 py-1.5 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 rounded-lg text-xs font-bold transition-all border border-blue-600/20 flex items-center gap-2"
                >
                    MTCS: {{ enabledMetrics.client.length }} ⚙️
                </button>

                <!-- Client Selector -->
                <div v-if="showSelector === 'client'" class="absolute right-0 mt-2 w-64 bg-slate-800 border border-slate-600 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in">
                    <div class="p-2 border-b border-slate-700 bg-slate-900/50 flex justify-between items-center">
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest px-2">Client Metrics</span>
                        <button @click="showSelector = null" class="text-slate-500 hover:text-white px-2">×</button>
                    </div>
                    <div class="max-h-64 overflow-y-auto p-1 custom-scrollbar">
                        <button 
                            v-for="metric in availableMetrics.client" 
                            :key="metric"
                            @click="toggleMetric('client', metric)"
                            :class="[
                                'w-full text-left px-3 py-2 rounded-lg text-xs transition-all flex justify-between items-center mb-0.5',
                                enabledMetrics.client.includes(metric) ? 'bg-blue-600/20 text-blue-400' : 'hover:bg-slate-700 text-slate-500'
                            ]"
                        >
                            {{ formatMetricName(metric) }}
                            <span v-if="enabledMetrics.client.includes(metric)" class="text-blue-500">✓</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            <div 
                v-for="(metric, idx) in enabledMetrics.client" 
                :key="'client-'+metric"
                class="bg-slate-800 p-4 rounded-xl border border-slate-700 hover:border-blue-500/50 transition-all flex flex-col h-44 group relative"
            >
                <div class="flex justify-between items-start z-10 w-full mb-1">
                    <div class="flex flex-col min-w-0 flex-1">
                        <span class="text-[9px] text-slate-500 font-mono tracking-tighter truncate">{{ metric }}</span>
                        <h3 class="text-slate-200 font-bold text-xs truncate">{{ formatMetricName(metric) }}</h3>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="text-lg font-mono font-bold text-blue-400">
                            {{ groupMetricsHistory.client[metric]?.length ? formatMetricValue(groupMetricsHistory.client[metric][groupMetricsHistory.client[metric].length - 1], metric) : '0' }}
                        </div>
                        <button 
                            @click="toggleMetric('client', metric)" 
                            class="opacity-0 group-hover:opacity-100 p-1 hover:bg-slate-700 rounded text-slate-500 hover:text-red-400 transition-all text-xs"
                            title="Remove chart"
                        >
                            ×
                        </button>
                    </div>
                </div>

                <!-- Chart Container -->
                <div class="flex-1 min-h-0 w-full">
                    <Line 
                        :data="{
                            labels: labels,
                            datasets: [{
                                label: metric,
                                data: groupMetricsHistory.client[metric] || [],
                                borderColor: getMetricColor('client', idx),
                                backgroundColor: getMetricColor('client', idx) + '15',
                                borderWidth: 2,
                                pointRadius: 0,
                                fill: true,
                                tension: 0.3
                            }]
                        }" 
                        :options="getChartOptions('client', idx)" 
                    />
                </div>
            </div>
        </div>
    </section>

    <!-- GROUP: SERVERS -->
    <section class="space-y-4 relative" :style="{ zIndex: showSelector === 'server' ? 60 : 5 }">
        <div class="flex justify-between items-center bg-slate-800/80 backdrop-blur p-3 rounded-xl border border-slate-700 shadow-xl relative z-20">
            <div class="flex items-center gap-3 font-medium">
                <span class="text-2xl">🛡️</span>
                <div>
                    <h2 class="text-base font-bold text-slate-100 leading-none">Server Group Metrics</h2>
                    <p class="text-[10px] text-slate-500 uppercase font-mono mt-1">Aggregated statistics for all server nodes</p>
                </div>
            </div>

            <div class="relative">
                <button 
                    @click="showSelector = showSelector === 'server' ? null : 'server'"
                    class="px-3 py-1.5 bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-400 rounded-lg text-xs font-bold transition-all border border-emerald-600/20 flex items-center gap-2"
                >
                    MTCS: {{ enabledMetrics.server.length }} ⚙️
                </button>

                <!-- Server Selector -->
                <div v-if="showSelector === 'server'" class="absolute right-0 mt-2 w-64 bg-slate-800 border border-slate-600 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in">
                    <div class="p-2 border-b border-slate-700 bg-slate-900/50 flex justify-between items-center">
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest px-2">Server Metrics</span>
                        <button @click="showSelector = null" class="text-slate-500 hover:text-white px-2">×</button>
                    </div>
                    <div class="max-h-64 overflow-y-auto p-1 custom-scrollbar">
                        <button 
                            v-for="metric in availableMetrics.server" 
                            :key="metric"
                            @click="toggleMetric('server', metric)"
                            :class="[
                                'w-full text-left px-3 py-2 rounded-lg text-xs transition-all flex justify-between items-center mb-0.5',
                                enabledMetrics.server.includes(metric) ? 'bg-emerald-600/20 text-emerald-400' : 'hover:bg-slate-700 text-slate-500'
                            ]"
                        >
                            {{ formatMetricName(metric) }}
                            <span v-if="enabledMetrics.server.includes(metric)" class="text-emerald-500">✓</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            <div 
                v-for="(metric, idx) in enabledMetrics.server" 
                :key="'server-'+metric"
                class="bg-slate-800 p-4 rounded-xl border border-slate-700 hover:border-emerald-500/50 transition-all flex flex-col h-44 group relative"
            >
                <div class="flex justify-between items-start z-10 w-full mb-1">
                    <div class="flex flex-col min-w-0 flex-1">
                        <span class="text-[9px] text-slate-500 font-mono tracking-tighter truncate">{{ metric }}</span>
                        <h3 class="text-slate-200 font-bold text-xs truncate">{{ formatMetricName(metric) }}</h3>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="text-lg font-mono font-bold text-emerald-400">
                            {{ groupMetricsHistory.server[metric]?.length ? formatMetricValue(groupMetricsHistory.server[metric][groupMetricsHistory.server[metric].length - 1], metric) : '0' }}
                        </div>
                        <button 
                            @click="toggleMetric('server', metric)" 
                            class="opacity-0 group-hover:opacity-100 p-1 hover:bg-slate-700 rounded text-slate-500 hover:text-red-400 transition-all text-xs"
                            title="Remove chart"
                        >
                            ×
                        </button>
                    </div>
                </div>

                <div class="flex-1 min-h-0 w-full">
                    <Line 
                        :data="{
                            labels: labels,
                            datasets: [{
                                label: metric,
                                data: groupMetricsHistory.server[metric] || [],
                                borderColor: getMetricColor('server', idx),
                                backgroundColor: getMetricColor('server', idx) + '15',
                                borderWidth: 2,
                                pointRadius: 0,
                                fill: true,
                                tension: 0.3
                            }]
                        }" 
                        :options="getChartOptions('server', idx)" 
                    />
                </div>
            </div>
        </div>
    </section>

    <!-- Empty State -->
    <div v-if="enabledMetrics.client.length === 0 && enabledMetrics.server.length === 0" class="flex-1 flex flex-col items-center justify-center text-slate-500 border-2 border-dashed border-slate-700 rounded-2xl py-20">
        <span class="text-5xl mb-4">📊</span>
        <p class="font-bold text-slate-400">No Metrics Selected</p>
        <p class="text-xs opacity-60">Open settings for Client or Server to begin monitoring</p>
    </div>

  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: 10px;
}
.animate-fade-in {
  animation: fadeIn 0.4s ease-out;
}
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
