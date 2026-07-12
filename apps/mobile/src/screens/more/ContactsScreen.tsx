import { useState } from "react";
import { addContact, removeContact, type SavedContact } from "../../contacts";
import { maskAddress } from "../../privacy";

type Props = {
  contacts: SavedContact[];
  setContacts: (c: SavedContact[]) => void;
  hideAddresses: boolean;
  onSelectContact: (c: SavedContact) => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function ContactsScreen({ contacts, setContacts, hideAddresses, onSelectContact, onToast }: Props) {
  const [label, setLabel] = useState("");
  const [address, setAddress] = useState("");

  return (
    <div className="card">
      <h2>Contacts</h2>
      <label className="label">Name</label>
      <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Alice" />
      <label className="label">Address</label>
      <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="1…" />
      <button
        type="button"
        className="primary"
        disabled={!label.trim() || !address.trim()}
        onClick={() => {
          setContacts(addContact(label, address));
          setLabel("");
          setAddress("");
          onToast("Contact saved.", "success");
        }}
      >
        Add contact
      </button>
      {contacts.length === 0 ? (
        <p className="muted">No saved contacts.</p>
      ) : (
        contacts.map((c) => (
          <div key={c.id} className="list-item">
            <div onClick={() => onSelectContact(c)}>
              <strong>{c.label}</strong>
              <div className="muted">{maskAddress(c.address, hideAddresses)}</div>
            </div>
            <button
              type="button"
              className="small ghost"
              onClick={() => {
                setContacts(removeContact(c.id));
                onToast("Contact removed.", "info");
              }}
            >
              Remove
            </button>
          </div>
        ))
      )}
    </div>
  );
}