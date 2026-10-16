// ---
// relationships:
//   implements: web-interface
// ---
function duration(milliseconds: number) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 172800) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} d`;
}
export function ago(value: string) {
  if (!value || value.startsWith("0001-")) return "never";
  return `${duration(Date.now() - Date.parse(value))} ago`;
}
export function until(value: string) {
  return `in ${duration(Date.parse(value) - Date.now())}`;
}
export function stamp(value: string) {
  return new Date(value).toISOString().slice(0, 19).replace("T", " ") + "Z";
}
