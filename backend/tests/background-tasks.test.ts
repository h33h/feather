import { afterEach, expect, it, vi } from 'vitest';
import { startBackgroundTasks } from '../server/background-tasks';

afterEach(() => vi.useRealTimers());
it('retains the task method context while scheduling', async () => {
  vi.useFakeTimers();
  const completed: string[] = [];
  const task = {
    name: 'cleanup',
    intervalMs: 100,
    async run() {
      completed.push(this.name);
    },
  };
  const running = startBackgroundTasks([task], () => {});
  await vi.advanceTimersByTimeAsync(100);
  expect(completed).toEqual(['cleanup']);
  running.stop();
});
it('stops scheduling when the runtime shuts down', async () => {
  vi.useFakeTimers();
  let completed = 0;
  const running = startBackgroundTasks([
    {
      name: 'cleanup',
      intervalMs: 100,
      run: async () => {
        completed++;
      },
    },
  ]);
  await vi.advanceTimersByTimeAsync(100);
  expect(completed).toBe(1);
  running.stop();
  running.stop();
  await vi.advanceTimersByTimeAsync(1000);
  expect(completed).toBe(1);
});
it('reports safe errors and continues processing the next interval', async () => {
  vi.useFakeTimers();
  let completed = 0;
  const errors: string[][] = [];
  const running = startBackgroundTasks(
    [
      {
        name: 'catalog',
        intervalMs: 100,
        run: async () => {
          if (!completed++) throw new Error('sensitive token contents');
        },
      },
    ],
    (name, code) => errors.push([name, code]),
  );
  await vi.advanceTimersByTimeAsync(200);
  expect(errors).toEqual([['catalog', 'UNEXPECTED_FAILURE']]);
  expect(completed).toBe(2);
  running.stop();
});
it('drains in-flight work before shutdown finishes and does not start another interval', async () => {
  vi.useFakeTimers();
  let complete!: () => void;
  let calls = 0;
  const gate = new Promise<void>((resolve) => {
    complete = resolve;
  });
  const running = startBackgroundTasks([
    {
      name: 'writing',
      intervalMs: 100,
      run: async () => {
        calls++;
        await gate;
      },
    },
  ]);
  await vi.advanceTimersByTimeAsync(100);
  let stopped = false;
  const stopping = Promise.resolve(running.stop()).then(() => {
    stopped = true;
  });
  await vi.advanceTimersByTimeAsync(1000);
  expect(calls).toBe(1);
  expect(stopped).toBe(false);
  complete();
  await stopping;
  expect(stopped).toBe(true);
});
