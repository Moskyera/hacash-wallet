type Props = {
  message: string;
  kind?: "success" | "info" | "error";
};

export default function Toast({ message, kind = "info" }: Props) {
  if (!message) return null;
  return (
    <div className={`toast toast-${kind}`} role="status">
      {message}
    </div>
  );
}