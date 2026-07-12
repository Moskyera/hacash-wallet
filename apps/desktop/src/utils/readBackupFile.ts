export type BackupFilePayload = {
  json: string;
  deleteSource?: string;
};

export function readBackupJsonFile(file: File): Promise<BackupFilePayload> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const json = typeof reader.result === "string" ? reader.result : "";
      if (!json.trim()) {
        reject(new Error("Backup file is empty"));
        return;
      }
      const deleteSource =
        typeof (file as File & { path?: string }).path === "string"
          ? (file as File & { path?: string }).path
          : undefined;
      resolve({ json, deleteSource });
    };
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read backup file"));
    reader.readAsText(file);
  });
}