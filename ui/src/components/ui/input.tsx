import * as React from "react";
import { cn } from "@/lib/utils";

const field =
  "flex w-full rounded-md border border-line bg-card px-2.5 text-[13px] text-ink placeholder:text-ink-3 focus-visible:border-kelp focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kelp/25 disabled:cursor-not-allowed disabled:opacity-50";

export function Input({ className, type = "text", ...props }: React.ComponentProps<"input">) {
  return <input type={type} className={cn(field, "h-8", className)} {...props} />;
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea className={cn(field, "min-h-[96px] py-2 leading-[1.5]", className)} {...props} />;
}
