from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    def __repr__(self):
        """
        Show column values when debugging.
        """
        fields_str = ", ".join(
            [f"{c.name}={getattr(self, c.name)!r}" for c in self.__mapper__.columns]
        )

        return f"{self.__class__.__name__}({fields_str})"


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(primary_key=True)
    dmi_sys_vendor: Mapped[str]
    dmi_product_uuid: Mapped[str]
    dmi_product_serial: Mapped[str]
    dmi_board_asset_tag: Mapped[str]
    os: Mapped[str]
    architecture: Mapped[str]
    cpu_model: Mapped[str]
    mem_total_bytes: Mapped[int]


class Job(Base):
    """
    The Jobs table - currently in use by tests.
    """

    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(primary_key=True)
    kind: Mapped[str]
    build_url: Mapped[str]
    build_hash: Mapped[str]
    sha: Mapped[str]
    branch: Mapped[str]
    original_branch: Mapped[str]
    cirrus_repo_owner: Mapped[str]
    cirrus_repo_name: Mapped[str]
    cirrus_task_id: Mapped[str]
    cirrus_task_name: Mapped[str]
    cirrus_build_id: Mapped[str]
    cirrus_pr: Mapped[str]
    github_check_suite_id: Mapped[str]
    repo_version: Mapped[str]
    machine_id: Mapped[int]
