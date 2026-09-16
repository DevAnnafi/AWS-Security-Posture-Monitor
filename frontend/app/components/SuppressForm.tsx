"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { updateFindingState, type FindingStatus } from "@/lib/api";

function defaultExpiry(): string {
  const date = new Date();
  date.setDate(date.getDate() + 90);
  return date.toISOString().slice(0, 10);
}

export function SuppressForm({
  findingId,
  status,
}: {
  findingId: string;
  status: FindingStatus;
}) {
  const router = useRouter();

  const [open, setOpen] = useState(false);
  const [suppressedBy, setSuppressedBy] = useState("");
  const [justification, setJustification] = useState("");
  const [expiresOn, setExpiresOn] = useState(defaultExpiry);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);

    try {
      await updateFindingState(findingId, {
        status: "suppressed",
        suppressed_by: suppressedBy,
        justification,
        expires_at: new Date(`${expiresOn}T00:00:00Z`).toISOString(),
      });
      setOpen(false);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed");
    } finally {
      setSaving(false);
    }
  }

  async function restore() {
    setSaving(true);
    setError(null);

    try {
      await updateFindingState(findingId, { status: "new" });
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed");
    } finally {
      setSaving(false);
    }
  }

  if (status === "suppressed") {
    return (
      <div>
        <button
          type="button"
          onClick={restore}
          disabled={saving}
          className="border border-ink px-4 py-2 text-sm hover:bg-paper-sunk disabled:opacity-50"
        >
          {saving ? "Restoring…" : "Restore this finding"}
        </button>
        {error && <p className="mt-2 text-sm text-unknown">{error}</p>}
      </div>
    );
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="border border-ink px-4 py-2 text-sm hover:bg-paper-sunk"
      >
        Suppress this finding
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="max-w-lg border border-rule p-5">
      <p className="mb-4 text-sm text-ink-soft">
        A suppressed finding stops appearing in the open count. It returns on
        its own once the expiry date passes.
      </p>

      <label className="block text-sm">
        Your name
        <input
          required
          value={suppressedBy}
          onChange={(e) => setSuppressedBy(e.target.value)}
          className="mt-1 w-full border border-rule bg-paper px-3 py-2"
        />
      </label>

      <label className="mt-4 block text-sm">
        Why this is safe to leave
        <textarea
          required
          rows={3}
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
          className="mt-1 w-full border border-rule bg-paper px-3 py-2"
        />
      </label>

      <label className="mt-4 block text-sm">
        Review again on
        <input
          required
          type="date"
          value={expiresOn}
          onChange={(e) => setExpiresOn(e.target.value)}
          className="mt-1 w-full border border-rule bg-paper px-3 py-2"
        />
      </label>

      {error && <p className="mt-4 text-sm text-unknown">{error}</p>}

      <div className="mt-5 flex gap-3">
        <button
          type="submit"
          disabled={saving}
          className="border border-ink bg-ink px-4 py-2 text-sm text-paper disabled:opacity-50"
        >
          {saving ? "Suppressing…" : "Suppress"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="px-4 py-2 text-sm text-ink-soft hover:text-ink"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}