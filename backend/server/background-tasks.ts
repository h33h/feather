export type BackgroundTask = {
  name: string;
  intervalMs: number;
  run: () => Promise<unknown>;
};
/** Owns recurring work and its shutdown, independently of runtime composition. */
export function startBackgroundTasks(
  tasks: readonly BackgroundTask[],
  report: (name: string, code: string) => void = (name, code) =>
    console.error('BACKGROUND_TASK_FAILED', name, code),
) {
  let stopped = false;
  let stopping: Promise<void> | undefined;
  const active = new Set<Promise<void>>();
  const timers = tasks.map((task) => {
    let running = false;
    const timer = setInterval(() => {
      if (stopped || running) return;
      running = true;
      const work = Promise.resolve()
        .then(() => {
          if (!stopped) return task.run();
        })
        .then(() => {})
        .catch((problem) => {
          const code =
            problem && typeof problem.code === 'string' && /^[A-Z_]{1,80}$/.test(problem.code)
              ? problem.code
              : 'UNEXPECTED_FAILURE';
          report(task.name, code);
        })
        .finally(() => {
          running = false;
          active.delete(work);
        });
      active.add(work);
    }, task.intervalMs);
    timer.unref?.();
    return timer;
  });
  return {
    stop: () => {
      stopped = true;
      timers.forEach((timer) => clearInterval(timer));
      return (stopping ??= Promise.allSettled([...active]).then(() => {}));
    },
  };
}
