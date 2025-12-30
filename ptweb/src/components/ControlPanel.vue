<script setup>
import { ref, computed, watch } from 'vue';
import { runPrepare, runCheck, runStart, runStop, generateConfig } from '../api';

const props = defineProps({
  state: String
});

const emit = defineEmits(['refresh-state']);

const loading = ref(false);
const generateParams = ref({
  template: 'both',
  count: '1',
  output_dir: 'web_output',
  numa_node: '0'
});

const handleAction = async (actionName, actionFn, args = null) => {
  loading.value = true;
  try {
    await actionFn(args);
    // Give a slight delay for state to update on backend
    setTimeout(() => emit('refresh-state'), 500);
  } catch (err) {
    console.error(`Error executing ${actionName}:`, err);
    alert(`Error executing ${actionName}: ${err.message}`);
  } finally {
    loading.value = false;
  }
};

const handleGenerate = () => handleAction('Generate', generateConfig, generateParams.value);

const handlePrepare = () => handleAction('Prepare', runPrepare, {
  build_dir: './build',
  config_dir: generateParams.value.output_dir
});

const handleCheck = () => handleAction('Check', runCheck);
const handleStart = () => handleAction('Start', runStart);
const handleStop = () => handleAction('Stop', runStop);

const isSafeToConfigure = computed(() => 
  ['IDLE', 'STOPPED', 'ERROR', 'RUN_DONE', '', undefined, null].includes(props.state)
);
const isPrepared = computed(() => props.state === 'PREPARED');
const isChecked = computed(() => props.state === 'CHECKED');

// Automatic state transitions
watch(() => props.state, (newState, oldState) => {
  // 1. After Prepare (hits PREPARED), automatically run Check
  if (newState === 'PREPARED' && oldState !== 'PREPARED' && oldState !== 'CHECKING') {
    console.log('State is PREPARED, triggering automatic Check');
    handleCheck();
  }
  
  // 2. After Test is Done (hits RUN_DONE), automatically run Stop (cleanup)
  if (newState === 'RUN_DONE' && oldState !== 'RUN_DONE' && oldState !== 'STOPPING') {
    console.log('State is RUN_DONE, triggering automatic Stop');
    handleStop();
  }
});
</script>

<template>
  <div class="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700 flex flex-col gap-6">
    <h2 class="text-xl font-bold text-slate-100 border-b border-slate-700 pb-2">Control Center</h2>

    <!-- Generation Controls -->
    <div class="space-y-3">
      <h3 class="text-sm font-semibold text-slate-400 uppercase tracking-wider">Configuration Generation</h3>
      <div class="grid grid-cols-2 gap-4">
        <label class="text-sm text-slate-300 flex flex-col gap-1">
          Template
          <select 
            v-model="generateParams.template"
            class="bg-slate-900 border border-slate-600 rounded p-2 text-slate-200 focus:ring-2 focus:ring-blue-500 outline-none"
          >
            <option value="both">Both (Client + Server)</option>
            <option value="client">Client Only</option>
            <option value="server">Server Only</option>
          </select>
        </label>
        <label class="text-sm text-slate-300 flex flex-col gap-1">
          Count
          <input 
            type="number" 
            v-model="generateParams.count"
            class="bg-slate-900 border border-slate-600 rounded p-2 text-slate-200 focus:ring-2 focus:ring-blue-500 outline-none"
          />
        </label>
      </div>
      <button 
        @click="handleGenerate" 
        :disabled="loading || !isSafeToConfigure"
        class="w-full py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-700 disabled:text-slate-500 rounded font-medium transition-colors cursor-pointer disabled:cursor-not-allowed"
      >
        Generate Config
      </button>
    </div>

    <div class="border-t border-slate-700"></div>

    <!-- Execution Controls -->
    <div class="space-y-4">
      <h3 class="text-sm font-semibold text-slate-400 uppercase tracking-wider">Test Execution</h3>
      
      <div class="flex gap-2">
          <button 
            @click="handlePrepare" 
            :disabled="loading || !isSafeToConfigure"
            class="flex-1 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 rounded font-bold shadow-md transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed"
          >
            1. Prepare
          </button>
          <button 
            @click="handleCheck" 
            :disabled="loading || !isPrepared"
            class="flex-1 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded font-bold shadow-md transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed"
          >
            2. Check
          </button>
      </div>

      <button 
        @click="handleStart" 
        :disabled="loading || !isChecked"
        class="w-full py-4 bg-green-600 hover:bg-green-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg font-bold text-lg shadow-lg shadow-green-900/50 transition-all active:scale-95 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
      >
        <span>▶</span> Start Test
      </button>

      <button 
        @click="handleStop" 
        :disabled="loading || state === 'STOPPED' || state === 'IDLE'"
        class="w-full py-3 bg-red-600 hover:bg-red-700 disabled:bg-slate-700 disabled:text-slate-500 rounded font-bold shadow-md transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed"
      >
        ■ Stop Test
      </button>
    </div>
  </div>
</template>
