import { DesignAsset, TaskButton } from './components';
export function ContentState({
  title,
  description,
  icon = 'state-layers',
  action,
  onAction,
  pending = false,
  error = false,
  compact = false,
  centered = false,
  actionPending = false,
}: {
  title: string;
  description: string;
  icon?: string;
  action?: string;
  onAction?: () => void;
  pending?: boolean;
  error?: boolean;
  compact?: boolean;
  centered?: boolean;
  actionPending?: boolean;
}) {
  return (
    <section
      className={
        'reference-state' + (compact ? ' compact' : '') + (centered ? ' centered-state' : '')
      }
      role={pending ? 'status' : error ? 'alert' : undefined}
    >
      <DesignAsset name={icon} width={40} />
      <h2>{title}</h2>
      <p>{description}</p>
      {action && onAction && (
        <TaskButton loading={actionPending} onClick={onAction}>
          {action}
        </TaskButton>
      )}
    </section>
  );
}
