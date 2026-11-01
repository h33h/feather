import { PublicState } from '../shared/ui/public-state';

export default function NotFound() {
  return (
    <PublicState
      title="Страница не найдена"
      message="Проверьте адрес или вернитесь к приложениям."
      actionLabel="К приложениям"
    />
  );
}
