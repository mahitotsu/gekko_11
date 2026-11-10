// 画面の小さな部品（D-48）。見た目は shadcn/ui の Card、Button、Badge、Alert、Table を写し、Tailwind のクラスだけで描く。
// style 属性で位置を決める部品（ポップオーバーなど）は使わない。画面の CSP（G32）が、インラインのスタイルを止めるからである（F-G102）。
// 意味は、色だけでなく、記号と文言でも伝える。記号は CSS の ::before で出し、要素の文（textContent）に混ぜない。
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

const cx = (...names: (string | false | undefined)[]) => names.filter(Boolean).join(" ");

type Variant = "primary" | "outline" | "ghost" | "danger";
const BUTTON: Record<Variant, string> = {
  primary: "bg-primary text-primary-foreground hover:opacity-90",
  outline: "border bg-card hover:bg-muted",
  ghost: "hover:bg-muted",
  danger: "border border-danger text-danger hover:bg-danger-soft",
};

export function Button({ variant = "outline", className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...rest}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-md px-3.5 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary",
        BUTTON[variant],
        className,
      )}
    />
  );
}

export function Card({ className, ...rest }: HTMLAttributes<HTMLElement>) {
  return <section {...rest} className={cx("rounded-xl border bg-card p-5 shadow-sm", className)} />;
}

type Tone = "verified" | "agent" | "danger" | "warning" | "neutral";
const BADGE: Record<Tone, string> = {
  verified: "border-verified/40 bg-verified-soft text-verified",
  agent: "border-agent/40 bg-agent-soft text-agent",
  danger: "border-danger/40 bg-danger-soft text-danger",
  warning: "border-warning/50 bg-warning-soft text-warning",
  neutral: "bg-muted text-muted-foreground",
};

/** 記号を ::before で出すクラス。記号は data-icon に置く。 */
export const ICON = "before:content-[attr(data-icon)]";

/** 小さな印。icon は、色の見分けがつかなくても意味が分かる記号にする。 */
export function Badge({ tone, icon, children, className }: { tone: Tone; icon?: string; children: ReactNode; className?: string }) {
  return (
    <span data-icon={icon} className={cx("inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold", icon && ICON, BADGE[tone], className)}>
      {children}
    </span>
  );
}

const ALERT: Record<Exclude<Tone, "agent" | "neutral">, string> = {
  verified: "border-verified/40 bg-verified-soft",
  danger: "border-danger/50 bg-danger-soft text-danger",
  warning: "border-warning/60 bg-warning-soft",
};
const ALERT_ICON = { verified: "✓", danger: "⚠", warning: "!" } as const;

/** 知らせの枠。誤りと警告は、記号と色で目立たせる。 */
export function Alert({ tone, className, children, ...rest }: HTMLAttributes<HTMLParagraphElement> & { tone: keyof typeof ALERT }) {
  return (
    <p {...rest} data-icon={ALERT_ICON[tone]} className={cx("flex gap-2 rounded-lg border px-4 py-3 text-sm font-medium before:font-bold", ICON, ALERT[tone], className)}>
      {children}
    </p>
  );
}

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className={cx("w-full border-collapse text-sm [&_td]:border-b [&_td]:px-3 [&_td]:py-1.5 [&_td:first-child]:whitespace-nowrap [&_td:first-child]:text-muted-foreground [&_tr:last-child_td]:border-b-0", className)}>
        {children}
      </table>
    </div>
  );
}
