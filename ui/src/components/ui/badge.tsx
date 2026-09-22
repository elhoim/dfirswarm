import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-sm border px-1.5 py-[1px] text-[11px] font-medium leading-[1.4] whitespace-nowrap [&_svg]:size-3",
  {
    variants: {
      variant: {
        neutral: "border-line bg-paper-2 text-ink-2",
        kelp: "border-kelp/30 bg-kelp-soft text-kelp-ink",
        saffron: "border-saffron/40 bg-saffron-soft text-saffron-ink",
        brick: "border-brick/30 bg-brick-soft text-brick-ink",
        slate: "border-slate/30 bg-slate-soft text-slate",
        moss: "border-moss/30 bg-moss-soft text-moss",
        outline: "border-line-2 bg-transparent text-ink-2",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

export type BadgeProps = React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>;

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
