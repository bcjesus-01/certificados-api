import type { DownloadLink } from "@/lib/api";
import { formatMinutes } from "@/lib/format";

export function DownloadButton({ link }: { link: DownloadLink }) {
  return (
    <div className="flex flex-col gap-2 border-t border-rule bg-paper p-5 sm:flex-row sm:items-center sm:justify-between">
      <a href={link.url} target="_blank" rel="noopener noreferrer" className="btn-primary">
        Baixar PDF assinado
      </a>
      <p className="text-xs text-ink-soft">O link vale por {formatMinutes(link.expires_in_seconds)}. Depois, consulte de novo.</p>
    </div>
  );
}
