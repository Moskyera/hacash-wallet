export type SavedContact = {
  id: string;
  label: string;
  address: string;
};

const STORAGE_KEY = "hacash_mobile_contacts_v1";

export function loadContacts(): SavedContact[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedContact[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveContacts(contacts: SavedContact[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts));
}

export function addContact(label: string, address: string): SavedContact[] {
  const next = [
    ...loadContacts(),
    { id: crypto.randomUUID(), label: label.trim(), address: address.trim() },
  ];
  saveContacts(next);
  return next;
}

export function removeContact(id: string): SavedContact[] {
  const next = loadContacts().filter((c) => c.id !== id);
  saveContacts(next);
  return next;
}