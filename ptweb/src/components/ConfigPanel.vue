<script setup>
import { ref, watch, computed } from 'vue';
import { updateConfig } from '../api';

const activeTab = ref('general');
const tabs = [
  { id: 'general', label: 'General & Scheduler' },
  { id: 'network', label: 'Network Stack' },
  { id: 'http', label: 'HTTP Settings' },
  { id: 'dpdk', label: 'DPDK & Interfaces' },
  { id: 'raw', label: 'Raw JSON / Upload' },
];

const loading = ref(false);
const fileInput = ref(null);

// Default structure based on config.json
const configObj = ref({
  scheduler: { prepare_duration_sec: 3, ramp_up_duration_sec: 10, sustain_duration_sec: 50, ramp_down_duration_sec: 10, close_duration_sec: 1 },
  objective: { type: 'HTTP_REQUESTS', value: 1000, requests_per_connection: 1 },
  http_config: { 
    use_https: 0, 
    cert_path: "./server.crt", 
    key_path: "./server.key",
    paths: [
      {
        path: "/hello",
        request_headers: ["User-Agent: perf_tool/1.0", "Accept: */*"],
        response_headers: ["Server: unetbsd", "Content-Type: text/plain"],
        response_body_size: 1024,
        response_code: 200,
        response_body: ""
      }
    ]
  },
  interface: { mtu: 2000 },
  network: {
    l2: { mac_address: "00:00:00:00:00:00" },
    l3: { src_ip_start: "192.168.1.10", src_ip_end: "192.168.1.20", dst_ip_start: "192.168.1.100", dst_ip_end: "192.168.1.110" },
    l4: { protocol: "TCP", src_port_start: 1000, src_port_end: 65000, dst_port_start: 8000, dst_port_end: 8010 }
  },
  dpdk_client: { 
    iface: "memif_c", 
    args: "--vdev=net_memif,id=0,role=client --proc-type=primary --file-prefix=memif_c", 
    is_dpdk_client: 1, 
    client_ring_idx: 0,
    client_lcore_id: 0,
    core_id: 1 
  },
  dpdk_server: { 
    iface: "memif_s", 
    args: "--vdev=net_memif,id=0,role=server --proc-type=primary --file-prefix=memif_s", 
    is_dpdk_client: 1, 
    client_ring_idx: 0,
    client_lcore_id: 0,
    core_id: 2 
  }
});

const rawConfig = ref(JSON.stringify(configObj.value, null, 2));
const jsonError = ref(null);

// Sync Logic
const syncToRaw = () => {
  rawConfig.value = JSON.stringify(configObj.value, null, 2);
};

const syncFromRaw = () => {
  try {
    const parsed = JSON.parse(rawConfig.value);
    // Ensure nested objects exist to avoid template errors
    if (!parsed.http_config) parsed.http_config = { paths: [] };
    if (!parsed.http_config.paths) parsed.http_config.paths = [];
    
    configObj.value = parsed;
    jsonError.value = null;
    return true;
  } catch (e) {
    jsonError.value = e.message;
    return false;
  }
};

watch(configObj, syncToRaw, { deep: true });

// When switching tabs, if leaving 'raw', we must validate and parse
const setActiveTab = (id) => {
  if (activeTab.value === 'raw' && id !== 'raw') {
    if (!syncFromRaw()) {
      alert("Invalid JSON in Raw tab. Please fix before switching.");
      return;
    }
  }
  activeTab.value = id;
};

// File Upload
const handleFileUpload = (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    rawConfig.value = e.target.result;
    syncFromRaw();
  };
  reader.readAsText(file);
};

const triggerFileUpload = () => fileInput.value.click();

const handleUpdate = async () => {
  loading.value = true;
  if (activeTab.value === 'raw') {
     if (!syncFromRaw()) {
       loading.value = false;
       return;
     }
  }

  try {
    await updateConfig(configObj.value);
    alert("Config applied successfully!");
  } catch (err) {
    console.error(err);
    alert("Failed to update config.");
  } finally {
    loading.value = false;
  }
};

// HTTP Path Helpers
const addPath = () => {
  configObj.value.http_config.paths.push({
    path: "/new-path",
    request_headers: ["User-Agent: perf_tool/1.0"],
    response_headers: ["Content-Type: text/plain"],
    response_body_size: 1024,
    response_code: 200,
    response_body: ""
  });
};

const removePath = (index) => {
  configObj.value.http_config.paths.splice(index, 1);
};

const addHeader = (headersArr) => {
  headersArr.push("Header-Name: value");
};

const removeHeader = (headersArr, idx) => {
  headersArr.splice(idx, 1);
};
</script>

<template>
  <div class="bg-slate-800 rounded-xl shadow-lg border border-slate-700 flex flex-col h-full overflow-hidden">
    <!-- Header with Tabs -->
    <div class="bg-slate-900/50 p-4 border-b border-slate-700">
      <div class="flex flex-wrap gap-2 mb-4">
        <button 
          v-for="tab in tabs" 
          :key="tab.id"
          @click="setActiveTab(tab.id)"
          :class="[
            'px-4 py-2 rounded-lg font-medium text-sm transition-all duration-200',
            activeTab === tab.id 
              ? 'bg-blue-600 text-white shadow-md shadow-blue-900/30 ring-1 ring-blue-500' 
              : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
          ]"
        >
          {{ tab.label }}
        </button>
      </div>
      
      <div class="flex justify-between items-center">
        <h2 class="text-lg font-bold text-slate-100 flex items-center gap-2">
           <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
           {{ tabs.find(t => t.id === activeTab).label }}
        </h2>
        <div class="flex gap-2">
            <button 
                @click="handleUpdate" 
                :disabled="loading"
                class="px-4 py-1.5 bg-green-600 hover:bg-green-700 disabled:bg-slate-700 rounded-md text-sm font-bold shadow-sm transition-all active:scale-95 flex items-center gap-2"
            >
                <span v-if="loading" class="animate-spin text-xs">⏳</span>
                {{ loading ? 'Saving...' : 'Apply Config' }}
            </button>
        </div>
      </div>
    </div>

    <!-- Scrollable Content Area -->
    <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
      
      <!-- GENERAL TAB -->
      <div v-if="activeTab === 'general'" class="space-y-8 animate-fade-in">
        <section>
          <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold mb-3 border-b border-slate-700 pb-1">Scheduler (Seconds)</h3>
          <div class="grid grid-cols-2 lg:grid-cols-5 gap-4">
            <div v-for="(val, key) in configObj.scheduler" :key="key" class="bg-slate-900 p-3 rounded border border-slate-700/50">
               <label class="text-xs text-slate-400 block mb-1 capitalize">{{ key.replace(/_/g, ' ').replace(' duration sec', '') }}</label>
               <input type="number" v-model.number="configObj.scheduler[key]" class="w-full bg-transparent text-slate-200 font-mono focus:outline-none border-b border-transparent focus:border-blue-500 transition-colors" />
            </div>
          </div>
        </section>

        <section>
           <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold mb-3 border-b border-slate-700 pb-1">Objective</h3>
           <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div class="bg-slate-900 p-3 rounded border border-slate-700/50">
                 <label class="text-xs text-slate-400 block mb-1">Type</label>
                 <select v-model="configObj.objective.type" class="w-full bg-transparent text-slate-200 focus:outline-none cursor-pointer">
                    <option value="HTTP_REQUESTS">HTTP_REQUESTS</option>
                    <option value="THROUGHPUT">THROUGHPUT</option>
                    <option value="CONCURRENT_USERS">CONCURRENT_USERS</option>
                 </select>
              </div>
              <div class="bg-slate-900 p-3 rounded border border-slate-700/50">
                 <label class="text-xs text-slate-400 block mb-1">Target Value</label>
                 <input type="number" v-model.number="configObj.objective.value" class="w-full bg-transparent text-slate-200 font-mono focus:outline-none border-b border-transparent focus:border-blue-500" />
              </div>
              <div class="bg-slate-900 p-3 rounded border border-slate-700/50">
                 <label class="text-xs text-slate-400 block mb-1">Reqs / Conn</label>
                 <input type="number" v-model.number="configObj.objective.requests_per_connection" class="w-full bg-transparent text-slate-200 font-mono focus:outline-none border-b border-transparent focus:border-blue-500" />
              </div>
           </div>
        </section>
      </div>

      <!-- NETWORK TAB -->
      <div v-if="activeTab === 'network'" class="space-y-8 animate-fade-in">
        <section>
            <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold mb-3 border-b border-slate-700 pb-1">Layer 3 (IP)</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-slate-900 p-4 rounded-lg border border-slate-700 relative overflow-hidden group">
                    <div class="absolute top-0 left-0 w-1 h-full bg-indigo-500"></div>
                    <h4 class="text-indigo-400 font-bold mb-3">Source &rarr;</h4>
                    <div class="space-y-2">
                        <div>
                             <label class="text-xs text-slate-500 block">Start IP</label>
                             <input type="text" v-model="configObj.network.l3.src_ip_start" class="w-full bg-slate-800/50 p-2 rounded text-slate-200 font-mono focus:ring-1 focus:ring-indigo-500 outline-none" />
                        </div>
                        <div>
                             <label class="text-xs text-slate-500 block">End IP</label>
                             <input type="text" v-model="configObj.network.l3.src_ip_end" class="w-full bg-slate-800/50 p-2 rounded text-slate-200 font-mono focus:ring-1 focus:ring-indigo-500 outline-none" />
                        </div>
                    </div>
                </div>
                <div class="bg-slate-900 p-4 rounded-lg border border-slate-700 relative overflow-hidden group">
                    <div class="absolute top-0 left-0 w-1 h-full bg-pink-500"></div>
                    <h4 class="text-pink-400 font-bold mb-3">&rarr; Destination</h4>
                    <div class="space-y-2">
                        <div>
                             <label class="text-xs text-slate-500 block">Start IP</label>
                             <input type="text" v-model="configObj.network.l3.dst_ip_start" class="w-full bg-slate-800/50 p-2 rounded text-slate-200 font-mono focus:ring-1 focus:ring-pink-500 outline-none" />
                        </div>
                        <div>
                             <label class="text-xs text-slate-500 block">End IP</label>
                             <input type="text" v-model="configObj.network.l3.dst_ip_end" class="w-full bg-slate-800/50 p-2 rounded text-slate-200 font-mono focus:ring-1 focus:ring-pink-500 outline-none" />
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section>
            <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold mb-3 border-b border-slate-700 pb-1">Layer 4 (Transport)</h3>
            <div class="bg-slate-900 p-4 rounded-lg border border-slate-700 grid grid-cols-2 md:grid-cols-5 gap-4 items-end">
                <div>
                     <label class="text-xs text-slate-500 block mb-1">Protocol</label>
                     <select v-model="configObj.network.l4.protocol" class="w-full bg-slate-800 p-2 rounded text-slate-200 outline-none border border-slate-700 focus:border-blue-500">
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                     </select>
                </div>
                <div>
                    <label class="text-xs text-slate-500 block mb-1">Src Port Start</label>
                    <input type="number" v-model.number="configObj.network.l4.src_port_start" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono outline-none border border-slate-700 focus:border-blue-500" />
                </div>
                <div>
                    <label class="text-xs text-slate-500 block mb-1">Src Port End</label>
                    <input type="number" v-model.number="configObj.network.l4.src_port_end" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono outline-none border border-slate-700 focus:border-blue-500" />
                </div>
                <div>
                    <label class="text-xs text-slate-500 block mb-1">Dst Port Start</label>
                    <input type="number" v-model.number="configObj.network.l4.dst_port_start" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono outline-none border border-slate-700 focus:border-blue-500" />
                </div>
                <div>
                    <label class="text-xs text-slate-500 block mb-1">Dst Port End</label>
                    <input type="number" v-model.number="configObj.network.l4.dst_port_end" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono outline-none border border-slate-700 focus:border-blue-500" />
                </div>
            </div>
        </section>
      </div>

      <!-- HTTP TAB -->
      <div v-if="activeTab === 'http'" class="space-y-8 animate-fade-in">
        <!-- TLS Settings -->
        <section>
          <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold mb-3 border-b border-slate-700 pb-1">TLS / HTTPS Settings</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-900 p-4 rounded-lg border border-slate-700">
              <div class="flex flex-col justify-center">
                  <label class="text-xs text-slate-400 mb-2">Enable HTTPS</label>
                  <label class="inline-flex items-center cursor-pointer">
                    <input type="checkbox" v-model="configObj.http_config.use_https" :true-value="1" :false-value="0" class="sr-only peer">
                    <div class="relative w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                  </label>
              </div>
              <div>
                  <label class="text-xs text-slate-500 block mb-1">Certificate Path</label>
                  <input type="text" v-model="configObj.http_config.cert_path" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono text-xs border border-slate-700 focus:border-blue-500 outline-none" />
              </div>
              <div>
                  <label class="text-xs text-slate-500 block mb-1">Key Path</label>
                  <input type="text" v-model="configObj.http_config.key_path" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono text-xs border border-slate-700 focus:border-blue-500 outline-none" />
              </div>
          </div>
        </section>

        <!-- Paths Configuration -->
        <section>
           <div class="flex justify-between items-center mb-3 border-b border-slate-700 pb-1">
             <h3 class="text-sm uppercase tracking-wider text-slate-500 font-bold">HTTP Paths & Headers</h3>
             <button @click="addPath" class="text-[10px] bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 px-2 py-1 rounded border border-blue-500/30 font-bold transition-all">+ Add Path</button>
           </div>
           
           <div class="space-y-6">
              <div v-for="(path, pIdx) in configObj.http_config.paths" :key="pIdx" class="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden shadow-inner">
                  <!-- Path Header -->
                  <div class="bg-slate-800/50 p-3 border-b border-slate-700 flex justify-between items-center">
                      <div class="flex items-center gap-3 flex-1 px-2">
                          <span class="text-blue-500 font-bold text-xs">PATH:</span>
                          <input type="text" v-model="path.path" class="bg-slate-950 px-3 py-1 rounded text-sm font-mono text-green-400 border border-slate-700 focus:border-blue-500 outline-none flex-1 max-w-md" />
                      </div>
                      <button @click="removePath(pIdx)" class="text-slate-500 hover:text-red-400 px-3 text-lg">&times;</button>
                  </div>

                  <div class="p-4 grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <!-- Headers Section -->
                      <div class="space-y-4">
                          <!-- Request Headers -->
                          <div>
                              <div class="flex justify-between items-center mb-2">
                                  <label class="text-[10px] text-slate-500 font-bold uppercase tracking-tight">Request Headers</label>
                                  <button @click="addHeader(path.request_headers)" class="text-[9px] text-blue-400 hover:underline">+ Add</button>
                              </div>
                              <div class="space-y-1">
                                  <div v-for="(h, hIdx) in path.request_headers" :key="hIdx" class="flex gap-1">
                                      <input type="text" v-model="path.request_headers[hIdx]" class="flex-1 bg-slate-950/50 p-1.5 rounded text-[11px] font-mono text-slate-300 border border-slate-800 focus:border-slate-600 outline-none" />
                                      <button @click="removeHeader(path.request_headers, hIdx)" class="text-slate-600 hover:text-red-500 px-1">&times;</button>
                                  </div>
                              </div>
                          </div>
                          <!-- Response Headers -->
                          <div>
                              <div class="flex justify-between items-center mb-2">
                                  <label class="text-[10px] text-slate-500 font-bold uppercase tracking-tight">Response Headers</label>
                                  <button @click="addHeader(path.response_headers)" class="text-[9px] text-emerald-400 hover:underline">+ Add</button>
                              </div>
                              <div class="space-y-1">
                                  <div v-for="(h, hIdx) in path.response_headers" :key="hIdx" class="flex gap-1">
                                      <input type="text" v-model="path.response_headers[hIdx]" class="flex-1 bg-slate-950/50 p-1.5 rounded text-[11px] font-mono text-slate-300 border border-slate-800 focus:border-slate-600 outline-none" />
                                      <button @click="removeHeader(path.response_headers, hIdx)" class="text-slate-600 hover:text-red-500 px-1">&times;</button>
                                  </div>
                              </div>
                          </div>
                      </div>

                      <!-- Status & Body Section -->
                      <div class="space-y-4 bg-slate-950/20 p-3 rounded-lg border border-slate-800/50">
                          <div class="grid grid-cols-2 gap-4">
                              <div>
                                  <label class="text-[10px] text-slate-500 font-bold uppercase block mb-1">Status Code</label>
                                  <input type="number" v-model.number="path.response_code" class="w-full bg-slate-950 p-2 rounded text-sm text-amber-400 font-mono border border-slate-800 focus:border-amber-600 outline-none" />
                              </div>
                              <div>
                                  <label class="text-[10px] text-slate-500 font-bold uppercase block mb-1">Body Size (Random)</label>
                                  <input type="number" v-model.number="path.response_body_size" class="w-full bg-slate-950 p-2 rounded text-sm text-slate-300 font-mono border border-slate-800 focus:border-slate-600 outline-none" />
                              </div>
                          </div>
                          <div>
                              <div class="flex justify-between items-center mb-1">
                                <label class="text-[10px] text-slate-500 font-bold uppercase">Static Response Body</label>
                                <span class="text-[9px] text-slate-600 italic">(Overrides random size if not empty)</span>
                              </div>
                              <textarea v-model="path.response_body" class="w-full h-24 bg-slate-950 p-2 rounded text-xs font-mono text-green-500 border border-slate-800 focus:border-blue-900 outline-none resize-none leading-relaxed" placeholder="Type specific response body content here..."></textarea>
                          </div>
                      </div>
                  </div>
              </div>
           </div>
        </section>
      </div>

      <!-- DPDK TAB -->
      <div v-if="activeTab === 'dpdk'" class="space-y-8 animate-fade-in">
           <div class="grid grid-cols-1 gap-6">
               <!-- Client -->
              <div class="bg-slate-900 p-5 rounded-lg border border-slate-700">
                  <h3 class="text-blue-400 font-bold mb-4 flex items-center gap-2">
                      <span class="text-lg">⚡</span> DPDK Client Settings
                  </h3>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div class="md:col-span-2">
                          <label class="text-xs text-slate-500 block mb-1">EAL Arguments (Raw ID)</label>
                          <input type="text" v-model="configObj.dpdk_client.args" class="w-full bg-slate-800 p-2 rounded text-slate-300 font-mono text-sm border border-slate-700 focus:border-blue-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Interface Name</label>
                           <input type="text" v-model="configObj.dpdk_client.iface" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-blue-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Master Core ID</label>
                           <input type="number" v-model.number="configObj.dpdk_client.core_id" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-blue-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Ring Index</label>
                           <input type="number" v-model.number="configObj.dpdk_client.client_ring_idx" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-blue-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Lcore ID</label>
                           <input type="number" v-model.number="configObj.dpdk_client.client_lcore_id" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-blue-500 outline-none" />
                      </div>
                  </div>
              </div>

              <!-- Server -->
              <div class="bg-slate-900 p-5 rounded-lg border border-slate-700">
                  <h3 class="text-pink-400 font-bold mb-4 flex items-center gap-2">
                      <span class="text-lg">🧬</span> DPDK Server Settings
                  </h3>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div class="md:col-span-2">
                          <label class="text-xs text-slate-500 block mb-1">EAL Arguments (Raw ID)</label>
                          <input type="text" v-model="configObj.dpdk_server.args" class="w-full bg-slate-800 p-2 rounded text-slate-300 font-mono text-sm border border-slate-700 focus:border-pink-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Interface Name</label>
                           <input type="text" v-model="configObj.dpdk_server.iface" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-pink-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Master Core ID</label>
                           <input type="number" v-model.number="configObj.dpdk_server.core_id" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-pink-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Ring Index</label>
                           <input type="number" v-model.number="configObj.dpdk_server.client_ring_idx" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-pink-500 outline-none" />
                      </div>
                      <div>
                           <label class="text-xs text-slate-500 block mb-1">Lcore ID</label>
                           <input type="number" v-model.number="configObj.dpdk_server.client_lcore_id" class="w-full bg-slate-800 p-2 rounded text-slate-200 font-mono border border-slate-700 focus:border-pink-500 outline-none" />
                      </div>
                  </div>
              </div>
           </div>
      </div>

      <!-- RAW TAB -->
      <div v-show="activeTab === 'raw'" class="h-full flex flex-col animate-fade-in">
        <div class="mb-4 flex gap-4">
           <div class="flex-1 bg-yellow-900/20 border border-yellow-700/50 p-3 rounded text-yellow-200 text-sm flex items-center gap-2">
              ⚠️ Edits here override all other tabs when applied.
           </div>
           <button @click="triggerFileUpload" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded font-medium flex-shrink-0 transition-colors">
              📂 Upload JSON
           </button>
           <input type="file" ref="fileInput" class="hidden" accept=".json" @change="handleFileUpload" />
        </div>
        <textarea
          class="flex-1 w-full bg-slate-950 border border-slate-700 rounded p-4 font-mono text-sm text-green-400 outline-none focus:ring-1 focus:ring-blue-500 resize-none leading-relaxed"
          v-model="rawConfig"
          spellcheck="false"
        ></textarea>
        <div v-if="jsonError" class="mt-2 text-red-400 text-sm font-mono bg-red-900/20 p-2 rounded border border-red-900/50">
           {{ jsonError }}
        </div>
      </div>
    
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 8px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: #1e293b; 
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: #475569; 
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: #64748b; 
}

.animate-fade-in {
  animation: fadeIn 0.2s ease-out forwards;
}

@keyframes fadeIn {
  from { opacity: 0.8; transform: translateY(5px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
