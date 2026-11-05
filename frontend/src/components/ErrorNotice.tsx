interface ErrorNoticeProps {
  message: string;
  onRetry?: () => void;
}

export function ErrorNotice({ message, onRetry }: ErrorNoticeProps) {
  return (
    <div role="alert" className="border-l-4 border-danger bg-danger-wash p-5">
      <p className="text-sm font-semibold text-danger">Não foi possível concluir a consulta</p>
      <p className="mt-1 max-w-reading text-sm">{message}</p>
      {onRetry ? (
        <button type="button" onClick={onRetry} className="btn-quiet mt-4">
          Tentar de novo
        </button>
      ) : null}
    </div>
  );
}
