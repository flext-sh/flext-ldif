"""Base classes for flext-ldif with typed config access.

Padrão consumidor: acesso tipado via self.config.ldif.

Usage:
    # Em services (herdam de LdifServiceBase):
    class MyService(LdifServiceBase[MyResult]):
        def execute(self) -> FlextResult[MyResult]:
            encoding = self.config.ldif.ldif_encoding  # Tipado!
            max_entries = self.config.ldif.ldif_max_entries

    # Acesso estático fora de services:
    config = LdifServiceBase.get_flext_config()
    ldif_config = LdifServiceBase.get_ldif_config()

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_core import FlextService, T

from flext_ldif.config import FlextLdifConfig, LdifFlextConfig


class LdifServiceBase(FlextService[T]):
    """Service base com config tipado.

    Padrão consumidor: acesso tipado via self.config.ldif.

    Herda de FlextService[T] para manter funcionalidades:
    - self.logger
    - execute() pattern
    - with_config()

    Acesso via instância:
        self.config.ldif.ldif_encoding
        self.config.ldif.ldif_max_entries

    Acesso estático:
        LdifServiceBase.get_flext_config().ldif.ldif_encoding
        LdifServiceBase.get_ldif_config().ldif_encoding
    """

    _injected_config: LdifFlextConfig | None = None

    # =========================================================================
    # ACESSO VIA INSTÂNCIA (self.config.*)
    # =========================================================================

    @property
    def config(self) -> LdifFlextConfig:
        """Config tipado com namespace ldif.

        Returns:
            LdifFlextConfig: FlextConfig tipado com acesso via .ldif

        """
        if self._injected_config is not None:
            return self._injected_config
        return LdifFlextConfig.get_global_instance()

    def with_config(self, config: LdifFlextConfig) -> Self:
        """DI: injeta config.

        Args:
            config: LdifFlextConfig instance to inject

        Returns:
            Self: Service instance with injected config

        """
        self._injected_config = config
        return self

    # =========================================================================
    # MÉTODOS ESTÁTICOS (para uso fora de services)
    # =========================================================================

    @staticmethod
    def get_flext_config() -> LdifFlextConfig:
        """Retorna LdifFlextConfig tipado (singleton).

        Returns:
            LdifFlextConfig: FlextConfig tipado com namespace ldif

        """
        return LdifFlextConfig.get_global_instance()

    @staticmethod
    def get_ldif_config() -> FlextLdifConfig:
        """Retorna FlextLdifConfig (singleton).

        Returns:
            FlextLdifConfig: LDIF configuration singleton

        """
        return LdifFlextConfig.get_global_instance().ldif


# Alias para backward compatibility
FlextLdifServiceBase = LdifServiceBase
