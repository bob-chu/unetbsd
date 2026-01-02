<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import StatusPanel from './components/StatusPanel.vue';
import ControlPanel from './components/ControlPanel.vue';
import ConfigPanel from './components/ConfigPanel.vue';
import MonitorPanel from './components/MonitorPanel.vue'; // Import
import { getState, checkHealth } from './api';

const state = ref('IDLE');
const health = ref(false);
const error = ref(null);
let interval = null;

// Tabs
const activeTab = ref('control'); // 'control' or 'monitor'

const refreshState = async () => {
  try {
    const healthRes = await checkHealth();
    health.value = healthRes.status === 200;

    const stateRes = await getState();
    if (stateRes.data && typeof stateRes.data === 'object' && stateRes.data.state) {
      state.value = stateRes.data.state;
    } else {
      state.value = stateRes.data;
    }
    error.value = null;
  } catch (err) {
    health.value = false;
  }
};

onMounted(() => {
  refreshState();
  interval = setInterval(refreshState, 2000);
});

onUnmounted(() => {
  if (interval) clearInterval(interval);
});
</script>

<template>
  <div class="min-h-screen bg-slate-900 text-slate-200 p-4 lg:p-8 flex flex-col">
    <!-- Header with Nav -->
    <header class="mb-6 bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-700 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-500">
          PTCP Web Controller
        </h1>
      </div>

      <div class="flex bg-slate-900 p-1 rounded-lg">
         <button 
           @click="activeTab = 'control'"
           :class="['px-6 py-2 rounded-md font-bold text-sm transition-all', activeTab === 'control' ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-white']"
         >
           ⚙️ Control & Config
         </button>
         <button 
           @click="activeTab = 'monitor'"
           :class="['px-6 py-2 rounded-md font-bold text-sm transition-all', activeTab === 'monitor' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white']"
         >
           📊 Live Monitor
         </button>
      </div>

      <div class="flex items-center gap-3">
         <div class="text-xs font-mono px-3 py-1 bg-slate-900 rounded border border-slate-700">
            State: <span :class="{'text-green-400': state === 'RUNNING', 'text-yellow-400': state === 'IDLE'}">{{ state }}</span>
         </div>
         <div class="w-3 h-3 rounded-full" :class="health ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500'"></div>
      </div>
    </header>

    <!-- Main Content Area -->
    <main class="flex-1 max-w-full">
       
       <!-- CONTROL TAB -->
       <div v-show="activeTab === 'control'" class="grid grid-cols-1 lg:grid-cols-3 gap-8 h-full">
          <div class="lg:col-span-2 flex flex-col">
            <ConfigPanel class="flex-1" />
          </div>
          <div class="lg:col-span-1 space-y-6">
            <StatusPanel :state="state" :health="health" :error="error" class="hidden lg:block" /> <!-- duplicated info but kept for structure -->
            <ControlPanel :state="state" @refresh-state="refreshState" @switch-to-monitor="activeTab = 'monitor'" />
          </div>
       </div>

       <!-- MONITOR TAB -->
       <div v-show="activeTab === 'monitor'">
          <MonitorPanel :isActive="activeTab === 'monitor'" :state="state" />
       </div>

    </main>
  </div>
</template>
