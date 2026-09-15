-- Template deactivation and document archiving (console lifecycle controls).
--
-- Deactivating a template hides it from "Generate from Template" and blocks
-- new generate_document calls against it, while every document already
-- generated from it is untouched - deactivation is a forward-looking gate,
-- not a delete, so existing signed documents remain fully valid.
ALTER TABLE templates ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;

-- Archiving a document is a separate axis from its signing-lifecycle status
-- (DRAFT/PENDING/PARTIALLY_SIGNED/SIGNED/EXPIRED) - a SIGNED document can be
-- archived without losing what "SIGNED" means, so this is a nullable
-- timestamp (archived vs not, and when) rather than another status value.
-- An archived document is excluded from the default Documents list and is
-- frozen - sealing/eSign against it is rejected until it is unarchived.
ALTER TABLE documents ADD COLUMN archived_at TIMESTAMPTZ;
CREATE INDEX idx_documents_archived ON documents(app_id, archived_at);
