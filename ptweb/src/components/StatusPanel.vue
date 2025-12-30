<script setup>
import { computed } from 'vue';

const props = defineProps({
  state: String,
  health: Boolean,
  error: String
});

const stateColors = {
  IDLE: 'bg-gray-500',
  PREPARING: 'bg-yellow-500',
  PREPARED: 'bg-blue-500',
  CHECKING: 'bg-yellow-600',
  CHECKED: 'bg-blue-600',
  STARTING: 'bg-indigo-500',
  RUNNING: 'bg-green-600',
  STOPPING: 'bg-red-400',
  STOPPED: 'bg-red-600',
  ERROR: 'bg-red-700',
  RUN_DONE: 'bg-green-800',
};

const stateColor = computed(() => stateColors[props.state] || 'bg-gray-700');
</script>

<template>
  <div class="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
    <h2 class="text-xl font-bold mb-4 text-slate-100">System Status</h2>
    
    <div class="flex items-center space-x-4 mb-4">
      <div class="text-sm text-slate-400">Current State:</div>
      <div :class="['px-4 py-1.5 rounded-full font-mono text-sm font-bold text-white shadow-sm', stateColor]">
        {{ state || 'UNKNOWN' }}
      </div>
    </div>

    <div class="flex items-center space-x-4">
      <div class="text-sm text-slate-400">Backend Health:</div>
      <div :class="['w-3 h-3 rounded-full', health ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500']"></div>
      <span class="text-xs text-slate-500">{{ health ? 'Connected' : 'Disconnected' }}</span>
    </div>

    <div v-if="error" class="mt-4 p-3 bg-red-900/30 border border-red-800 text-red-200 text-sm rounded">
      Error: {{ error }}
    </div>
  </div>
</template>
