// ---
// relationships:
//   implements: web-interface
// ---
const icons = {
  edit: "M12 20h9M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z",
  add: "M12 5v14M5 12h14",
};

export function RowAction({
  href,
  text,
  name,
  icon,
}: {
  href: string;
  text: string;
  name: string;
  icon: keyof typeof icons;
}) {
  return (
    <a className="row-action" href={href} aria-label={name}>
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        width="16"
        height="16"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d={icons[icon]} />
      </svg>
      {text}
    </a>
  );
}
