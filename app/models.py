from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DossierRecord(Base):
    __tablename__ = "dossiers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    dossier_id: Mapped[str] = mapped_column(String(256), index=True)
    proposal_json: Mapped[str] = mapped_column(Text)


class Evaluation(Base):
    __tablename__ = "evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evaluation_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    input_digest: Mapped[str] = mapped_column(String(64))
    request_json: Mapped[str] = mapped_column(Text)
    response_json: Mapped[str] = mapped_column(Text)
    verifier_json: Mapped[str] = mapped_column(Text)
    committed_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ReceiptRecord(Base):
    __tablename__ = "receipts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evaluation_id: Mapped[str] = mapped_column(ForeignKey("evaluations.evaluation_id"))
    dossier_id: Mapped[str] = mapped_column(String(256))
    call_id: Mapped[str] = mapped_column(String(128))
    receipt_id: Mapped[str] = mapped_column(String(512))
    accepted: Mapped[bool] = mapped_column(Boolean)
    outcome: Mapped[str] = mapped_column(String(32))

    __table_args__ = (UniqueConstraint("evaluation_id", "dossier_id", "call_id"),)
