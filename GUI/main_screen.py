from PyQt5 import QtWidgets, QtCore, QtGui
import sys
import math


# ─────────────────────────────────────────────
#  COULEURS & CONSTANTES
# ─────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_SIDEBAR   = "#111827"
BG_CONTENT   = "#161d2b"
BG_CARD      = "#1a2235"
BG_INPUT     = "#111827"
ACCENT       = "#6366f1"
ACCENT_HOVER = "#4f46e5"
TEXT_WHITE   = "#f1f5f9"
TEXT_GRAY    = "#94a3b8"
TEXT_BLUE    = "#818cf8"
BORDER       = "#1e293b"
ACTIVE_BTN   = "#312e81"
GREEN        = "#22c55e"
RED_ERR      = "#ef4444"


# ─────────────────────────────────────────────
#  ALGORITHME AFFINE  (ta logique, inchangée)
# ─────────────────────────────────────────────
def chiffrement_affine(plain_text: str, a: int, b: int) -> str:
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            x = ord(char.upper()) - ord('A')
            y = (a * x + b) % 26
            cipher_text += chr(y + ord('A'))
        else:
            cipher_text += char
    return cipher_text


def dechiffrement_affine(cipher_text: str, a: int, b: int) -> str:
    plain_text = ""
    a_inv = pow(a, -1, 26)
    for char in cipher_text:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plain_text += chr(x + ord('A'))
        else:
            plain_text += char
    return plain_text


def valeurs_a_valides():
    return [a for a in range(1, 30) if math.gcd(a, 26) == 1]


# ─────────────────────────────────────────────
#  WIDGET RÉSULTAT GÉNÉRIQUE
# ─────────────────────────────────────────────
class ResultRow(QtWidgets.QFrame):
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border-radius: 10px;
                border: 1px solid {BORDER};
            }}
        """)
        self.setMinimumHeight(54)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(18, 10, 12, 10)
        layout.setSpacing(12)

        self.lbl_name = QtWidgets.QLabel(label)
        self.lbl_name.setFixedWidth(180)
        self.lbl_name.setStyleSheet(
            f"color:{TEXT_WHITE}; font-weight:600; font-size:13px; background:transparent; border:none;")

        self.lbl_value = QtWidgets.QLabel("—")
        self.lbl_value.setWordWrap(True)
        self.lbl_value.setStyleSheet(
            f"color:{TEXT_GRAY}; font-size:13px; font-family:Consolas,monospace; background:transparent; border:none;")
        self.lbl_value.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

        self.btn_copy = QtWidgets.QPushButton("⧉")
        self.btn_copy.setFixedSize(30, 30)
        self.btn_copy.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_copy.setToolTip("Copier")
        self.btn_copy.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border: none; border-radius: 6px;
                color: {TEXT_GRAY}; font-size: 15px;
            }}
            QPushButton:hover {{ background-color: #1e293b; color: {TEXT_WHITE}; }}
        """)
        self.btn_copy.clicked.connect(self._copy)

        layout.addWidget(self.lbl_name)
        layout.addWidget(self.lbl_value, 1)
        layout.addWidget(self.btn_copy)

    def set_value(self, value: str, error: bool = False):
        self.lbl_value.setText(value)
        color = RED_ERR if error else TEXT_WHITE
        self.lbl_value.setStyleSheet(
            f"color:{color}; font-size:13px; font-family:Consolas,monospace; background:transparent; border:none;")

    def clear_value(self):
        self.lbl_value.setText("—")
        self.lbl_value.setStyleSheet(
            f"color:{TEXT_GRAY}; font-size:13px; font-family:Consolas,monospace; background:transparent; border:none;")

    def _copy(self):
        val = self.lbl_value.text()
        if val != "—" and not val.startswith("Erreur"):
            QtWidgets.QApplication.clipboard().setText(val)
            self.btn_copy.setText("✓")
            QtCore.QTimer.singleShot(1200, lambda: self.btn_copy.setText("⧉"))


# ─────────────────────────────────────────────
#  PAGE : CHIFFREMENT AFFINE
# ─────────────────────────────────────────────
class AffinePage(QtWidgets.QWidget):
    A_VALIDES = valeurs_a_valides()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BG_CONTENT};")

        # Scroll area pour les petits écrans
        scroll = QtWidgets.QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setStyleSheet("background:transparent; border:none;")

        container = QtWidgets.QWidget()
        container.setStyleSheet(f"background-color: {BG_CONTENT};")
        scroll.setWidget(container)

        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        root = QtWidgets.QVBoxLayout(container)
        root.setContentsMargins(36, 32, 36, 32)
        root.setSpacing(0)

        # ── Titre ──────────────────────────────
        title = QtWidgets.QLabel("Chiffrement Affine")
        title.setStyleSheet(
            f"color:{TEXT_WHITE}; font-size:22px; font-weight:700; background:transparent;")
        subtitle = QtWidgets.QLabel(
            "Chiffrement symétrique par substitution  ·  y = (a·x + b) mod 26")
        subtitle.setStyleSheet(f"color:{TEXT_GRAY}; font-size:12px; background:transparent;")
        root.addWidget(title)
        root.addWidget(subtitle)
        root.addSpacing(24)

        # ── Zone de texte ──────────────────────
        hdr = QtWidgets.QHBoxLayout()
        lbl_in = QtWidgets.QLabel("TEXTE D'ENTRÉE")
        lbl_in.setStyleSheet(
            f"color:{TEXT_BLUE}; font-size:11px; font-weight:600; letter-spacing:1px; background:transparent;")
        self.char_count = QtWidgets.QLabel("0 caractères")
        self.char_count.setStyleSheet(f"color:{TEXT_GRAY}; font-size:11px; background:transparent;")
        hdr.addWidget(lbl_in)
        hdr.addStretch()
        hdr.addWidget(self.char_count)
        root.addLayout(hdr)
        root.addSpacing(8)

        self.text_input = QtWidgets.QTextEdit()
        self.text_input.setPlaceholderText("Entrez votre texte ici…")
        self.text_input.setFixedHeight(110)
        self.text_input.setStyleSheet(f"""
            QTextEdit {{
                background-color: {BG_INPUT};
                color: {TEXT_WHITE};
                border: 1px solid {BORDER};
                border-radius: 10px;
                padding: 12px;
                font-size: 13px;
            }}
            QTextEdit:focus {{ border: 1px solid {ACCENT}; }}
        """)
        self.text_input.textChanged.connect(self._update_char_count)
        root.addWidget(self.text_input)
        root.addSpacing(18)

        # ── Paramètres a et b ──────────────────
        lbl_params = QtWidgets.QLabel("PARAMÈTRES DE CLÉ")
        lbl_params.setStyleSheet(
            f"color:{TEXT_BLUE}; font-size:11px; font-weight:600; letter-spacing:1px; background:transparent;")
        root.addWidget(lbl_params)
        root.addSpacing(8)

        params_row = QtWidgets.QHBoxLayout()
        params_row.setSpacing(16)

        # --- a ---
        col_a = QtWidgets.QVBoxLayout()
        col_a.setSpacing(6)
        lbl_a = QtWidgets.QLabel("Valeur de a  (pgcd(a, 26) = 1)")
        lbl_a.setStyleSheet(f"color:{TEXT_GRAY}; font-size:12px; background:transparent;")

        self.combo_a = QtWidgets.QComboBox()
        for val in self.A_VALIDES:
            self.combo_a.addItem(str(val))
        self.combo_a.setCurrentIndex(1)
        self.combo_a.setFixedHeight(38)
        self.combo_a.setStyleSheet(self._combo_style())

        info_a = QtWidgets.QLabel("✓  Toutes les valeurs listées sont valides")
        info_a.setStyleSheet(f"color:{GREEN}; font-size:11px; background:transparent;")

        col_a.addWidget(lbl_a)
        col_a.addWidget(self.combo_a)
        col_a.addWidget(info_a)

        # --- b ---
        col_b = QtWidgets.QVBoxLayout()
        col_b.setSpacing(6)
        lbl_b = QtWidgets.QLabel("Valeur de b  (0 – 25)")
        lbl_b.setStyleSheet(f"color:{TEXT_GRAY}; font-size:12px; background:transparent;")

        self.spin_b = QtWidgets.QSpinBox()
        self.spin_b.setRange(0, 25)
        self.spin_b.setValue(7)
        self.spin_b.setFixedHeight(38)
        self.spin_b.setStyleSheet(self._spinbox_style())

        self.info_b = QtWidgets.QLabel("b = 7")
        self.info_b.setStyleSheet(f"color:{TEXT_GRAY}; font-size:11px; background:transparent;")
        self.spin_b.valueChanged.connect(lambda v: self.info_b.setText(f"b = {v}"))

        col_b.addWidget(lbl_b)
        col_b.addWidget(self.spin_b)
        col_b.addWidget(self.info_b)

        params_row.addLayout(col_a, 1)
        params_row.addLayout(col_b, 1)
        root.addLayout(params_row)
        root.addSpacing(20)

        # ── Boutons ────────────────────────────
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addStretch()

        self.btn_reset = QtWidgets.QPushButton("↺")
        self.btn_reset.setFixedSize(40, 36)
        self.btn_reset.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_reset.setToolTip("Réinitialiser")
        self.btn_reset.setStyleSheet(self._icon_btn_style())
        self.btn_reset.clicked.connect(self._reset)

        self.btn_chiffrer = QtWidgets.QPushButton("🔒  Chiffrer")
        self.btn_chiffrer.setFixedHeight(36)
        self.btn_chiffrer.setMinimumWidth(120)
        self.btn_chiffrer.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_chiffrer.setStyleSheet(self._primary_btn_style())
        self.btn_chiffrer.clicked.connect(self._chiffrer)

        self.btn_dechiffrer = QtWidgets.QPushButton("🔓  Déchiffrer")
        self.btn_dechiffrer.setFixedHeight(36)
        self.btn_dechiffrer.setMinimumWidth(120)
        self.btn_dechiffrer.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_dechiffrer.setStyleSheet(self._secondary_btn_style())
        self.btn_dechiffrer.clicked.connect(self._dechiffrer)

        btn_row.addWidget(self.btn_reset)
        btn_row.addSpacing(8)
        btn_row.addWidget(self.btn_chiffrer)
        btn_row.addSpacing(8)
        btn_row.addWidget(self.btn_dechiffrer)
        root.addLayout(btn_row)
        root.addSpacing(26)

        # ── Résultats ──────────────────────────
        lbl_res = QtWidgets.QLabel("RÉSULTAT")
        lbl_res.setStyleSheet(
            f"color:{TEXT_BLUE}; font-size:11px; font-weight:600; letter-spacing:1px; background:transparent;")
        root.addWidget(lbl_res)
        root.addSpacing(10)

        self.row_resultat  = ResultRow("Texte traité")
        self.row_cle       = ResultRow("Clé utilisée  (a, b)")
        self.row_operation = ResultRow("Opération")

        for row in [self.row_resultat, self.row_cle, self.row_operation]:
            root.addWidget(row)
            root.addSpacing(6)

        # ── Rappel formule ─────────────────────
        root.addSpacing(10)
        formule_frame = QtWidgets.QFrame()
        formule_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1117;
                border-radius: 8px;
                border: 1px solid {BORDER};
            }}
        """)
        fl = QtWidgets.QVBoxLayout(formule_frame)
        fl.setContentsMargins(16, 12, 16, 12)
        fl.setSpacing(5)

        lbl_ft = QtWidgets.QLabel("Rappel mathématique")
        lbl_ft.setStyleSheet(
            f"color:{TEXT_BLUE}; font-size:11px; font-weight:600; letter-spacing:1px; background:transparent;")
        lbl_f1 = QtWidgets.QLabel("Chiffrement   :   y = (a · x + b) mod 26")
        lbl_f2 = QtWidgets.QLabel("Déchiffrement :   x = a⁻¹ · (y − b) mod 26")
        lbl_f3 = QtWidgets.QLabel(
            f"Valeurs de a valides : {', '.join(str(v) for v in self.A_VALIDES)}")

        for lbl in [lbl_f1, lbl_f2]:
            lbl.setStyleSheet(
                f"color:{TEXT_WHITE}; font-size:12px; font-family:Consolas,monospace; background:transparent;")
        lbl_f3.setStyleSheet(f"color:{TEXT_GRAY}; font-size:11px; background:transparent;")

        fl.addWidget(lbl_ft)
        fl.addSpacing(4)
        fl.addWidget(lbl_f1)
        fl.addWidget(lbl_f2)
        fl.addSpacing(4)
        fl.addWidget(lbl_f3)
        root.addWidget(formule_frame)
        root.addStretch()

    # ─── Logique ────────────────────────────────
    def _get_params(self):
        return int(self.combo_a.currentText()), self.spin_b.value()

    def _chiffrer(self):
        texte = self.text_input.toPlainText()
        if not texte.strip():
            return
        a, b = self._get_params()
        resultat = chiffrement_affine(texte, a, b)
        self.row_resultat.set_value(resultat)
        self.row_cle.set_value(f"a = {a}   ·   b = {b}")
        self.row_operation.set_value("Chiffrement  →  y = (a·x + b) mod 26")

    def _dechiffrer(self):
        texte = self.text_input.toPlainText()
        if not texte.strip():
            return
        a, b = self._get_params()
        try:
            resultat = dechiffrement_affine(texte, a, b)
            self.row_resultat.set_value(resultat)
            self.row_cle.set_value(
                f"a = {a}   ·   b = {b}   ·   a⁻¹ mod 26 = {pow(a, -1, 26)}")
            self.row_operation.set_value("Déchiffrement  →  x = a⁻¹·(y − b) mod 26")
        except Exception as e:
            self.row_resultat.set_value(f"Erreur : {e}", error=True)

    def _reset(self):
        self.text_input.clear()
        self.combo_a.setCurrentIndex(1)
        self.spin_b.setValue(7)
        for row in [self.row_resultat, self.row_cle, self.row_operation]:
            row.clear_value()

    def _update_char_count(self):
        n = len(self.text_input.toPlainText())
        self.char_count.setText(f"{n} caractère{'s' if n != 1 else ''}")

    # ─── Styles ─────────────────────────────────
    def _primary_btn_style(self):
        return f"""
            QPushButton {{
                background-color: {ACCENT};
                color: white; border: none;
                border-radius: 8px; padding: 0 16px;
                font-size: 13px; font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {ACCENT_HOVER}; }}
            QPushButton:pressed {{ background-color: #3730a3; }}
        """

    def _secondary_btn_style(self):
        return f"""
            QPushButton {{
                background-color: #1e293b;
                color: {TEXT_GRAY};
                border: 1px solid {BORDER};
                border-radius: 8px; padding: 0 14px;
                font-size: 13px;
            }}
            QPushButton:hover {{ background-color: #263347; color: {TEXT_WHITE}; }}
        """

    def _icon_btn_style(self):
        return f"""
            QPushButton {{
                background-color: #1e293b;
                color: {TEXT_GRAY};
                border: 1px solid {BORDER};
                border-radius: 8px; font-size: 16px;
            }}
            QPushButton:hover {{ background-color: #263347; color: {TEXT_WHITE}; }}
        """

    def _combo_style(self):
        return f"""
            QComboBox {{
                background-color: {BG_INPUT};
                color: {TEXT_WHITE};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 0 12px;
                font-size: 13px;
            }}
            QComboBox:focus {{ border: 1px solid {ACCENT}; }}
            QComboBox::drop-down {{ border: none; width: 28px; }}
            QComboBox QAbstractItemView {{
                background-color: {BG_CARD};
                color: {TEXT_WHITE};
                border: 1px solid {BORDER};
                selection-background-color: {ACCENT};
            }}
        """

    def _spinbox_style(self):
        return f"""
            QSpinBox {{
                background-color: {BG_INPUT};
                color: {TEXT_WHITE};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 0 12px;
                font-size: 13px;
            }}
            QSpinBox:focus {{ border: 1px solid {ACCENT}; }}
            QSpinBox::up-button, QSpinBox::down-button {{
                background-color: #1e293b;
                border: none; width: 20px;
            }}
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
                background-color: #263347;
            }}
        """


# ─────────────────────────────────────────────
#  PAGE PLACEHOLDER  (bientôt disponible)
# ─────────────────────────────────────────────
class PlaceholderPage(QtWidgets.QWidget):
    def __init__(self, title: str, subtitle: str = "", icon: str = "🔒", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BG_CONTENT};")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setAlignment(QtCore.Qt.AlignCenter)
        layout.setSpacing(12)

        lbl_icon = QtWidgets.QLabel(icon)
        lbl_icon.setAlignment(QtCore.Qt.AlignCenter)
        lbl_icon.setStyleSheet("font-size: 44px; background: transparent;")

        lbl_title = QtWidgets.QLabel(title)
        lbl_title.setAlignment(QtCore.Qt.AlignCenter)
        lbl_title.setStyleSheet(
            f"color:{TEXT_WHITE}; font-size:20px; font-weight:700; background:transparent;")

        badge = QtWidgets.QLabel("🚧  Bientôt disponible")
        badge.setAlignment(QtCore.Qt.AlignCenter)
        badge.setStyleSheet(f"""
            color: #f59e0b;
            background-color: #1c1a0d;
            border: 1px solid #78350f;
            border-radius: 8px;
            padding: 6px 18px;
            font-size: 12px;
            font-weight: 600;
        """)

        layout.addWidget(lbl_icon)
        layout.addWidget(lbl_title)
        if subtitle:
            lbl_sub = QtWidgets.QLabel(subtitle)
            lbl_sub.setAlignment(QtCore.Qt.AlignCenter)
            lbl_sub.setStyleSheet(f"color:{TEXT_GRAY}; font-size:12px; background:transparent;")
            layout.addWidget(lbl_sub)
        layout.addSpacing(8)
        layout.addWidget(badge)
        layout.addStretch()


# ─────────────────────────────────────────────
#  BOUTON SIDEBAR
# ─────────────────────────────────────────────
class SidebarButton(QtWidgets.QPushButton):
    def __init__(self, icon: str, label: str, parent=None):
        super().__init__(parent)
        self.setText(f"  {icon}  {label}")
        self.setFixedHeight(42)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setCheckable(True)
        self.setActive(False)

    def setActive(self, active: bool):
        if active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ACTIVE_BTN};
                    color: {TEXT_WHITE};
                    border: none; border-radius: 8px;
                    text-align: left; padding-left: 6px;
                    font-size: 13px; font-weight: 600;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {TEXT_GRAY};
                    border: none; border-radius: 8px;
                    text-align: left; padding-left: 6px;
                    font-size: 13px;
                }}
                QPushButton:hover {{
                    background-color: #1e293b;
                    color: {TEXT_WHITE};
                }}
            """)


# ─────────────────────────────────────────────
#  FENÊTRE PRINCIPALE
# ─────────────────────────────────────────────
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CrypterHub — Outil d'algorithmes de cryptage")
        self.setMinimumSize(960, 700)
        self.resize(1140, 800)
        self.setStyleSheet(f"background-color: {BG_DARK};")

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_h = QtWidgets.QHBoxLayout(central)
        root_h.setContentsMargins(0, 0, 0, 0)
        root_h.setSpacing(0)

        # ── SIDEBAR ───────────────────────────
        sidebar = QtWidgets.QFrame()
        sidebar.setFixedWidth(228)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_SIDEBAR};
                border-right: 1px solid {BORDER};
            }}
        """)
        sb_layout = QtWidgets.QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(14, 22, 14, 22)
        sb_layout.setSpacing(4)

        # Logo
        logo_row = QtWidgets.QHBoxLayout()
        logo_icon = QtWidgets.QLabel("🛡")
        logo_icon.setStyleSheet("font-size:22px; background:transparent;")
        app_name = QtWidgets.QLabel("CrypterHub")
        app_name.setStyleSheet(
            f"color:{TEXT_WHITE}; font-size:15px; font-weight:700; background:transparent;")
        app_desc = QtWidgets.QLabel("Outil d'algorithmes de cryptage")
        app_desc.setStyleSheet(f"color:{TEXT_GRAY}; font-size:9px; background:transparent;")
        name_col = QtWidgets.QVBoxLayout()
        name_col.setSpacing(1)
        name_col.addWidget(app_name)
        name_col.addWidget(app_desc)
        logo_row.addWidget(logo_icon)
        logo_row.addLayout(name_col)
        logo_row.addStretch()
        sb_layout.addLayout(logo_row)
        sb_layout.addSpacing(20)

        sec_lbl = QtWidgets.QLabel("ALGORITHMES")
        sec_lbl.setStyleSheet(
            f"color:{TEXT_GRAY}; font-size:10px; letter-spacing:1.2px;"
            f"font-weight:600; background:transparent;")
        sb_layout.addWidget(sec_lbl)
        sb_layout.addSpacing(6)

        # Stack + pages
        self.stack = QtWidgets.QStackedWidget()
        self.stack.setStyleSheet(f"background-color: {BG_CONTENT};")
        self._nav_buttons: list[SidebarButton] = []

        pages_def = [
            ("⊞",  "Tous les algorithmes",
             PlaceholderPage("Tous les algorithmes",
                             "Sélectionnez un algorithme dans le menu", "⊞")),
            ("＃",  "Hash",
             PlaceholderPage("Hash", "MD5, SHA-1, SHA-256, SHA-512…", "＃")),
            ("🔒", "Chiffrement symétrique",
             AffinePage()),
            ("🔑", "Chiffrement asymétrique",
             PlaceholderPage("Chiffrement asymétrique", "RSA, ECC…", "🔑")),
            ("</>", "Encodage",
             PlaceholderPage("Encodage", "Base64, Hex…", "📝")),
            ("🛡",  "HMAC",
             PlaceholderPage("HMAC", "Codes d'authentification de message")),
            ("···", "Autres",
             PlaceholderPage("Autres", "Algorithmes supplémentaires", "⚙")),
        ]

        for icon, label, page in pages_def:
            btn = SidebarButton(icon, label)
            idx = self.stack.count()
            self.stack.addWidget(page)
            btn.clicked.connect(
                lambda checked, i=idx, b=btn: self._navigate(i, b))
            sb_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        sb_layout.addStretch()

        # Bloc À propos
        about_frame = QtWidgets.QFrame()
        about_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1117;
                border-radius: 8px;
                border: 1px solid {BORDER};
            }}
        """)
        al = QtWidgets.QVBoxLayout(about_frame)
        al.setContentsMargins(12, 10, 12, 10)
        al.setSpacing(4)
        lbl_about = QtWidgets.QLabel("À PROPOS")
        lbl_about.setStyleSheet(
            f"color:{TEXT_BLUE}; font-size:9px; font-weight:700;"
            f"letter-spacing:1px; background:transparent; border:none;")
        lbl_desc = QtWidgets.QLabel(
            "CrypterHub est un outil pédagogique\n"
            "permettant d'explorer et de tester\n"
            "les principaux algorithmes de\n"
            "cryptage et d'encodage.")
        lbl_desc.setStyleSheet(
            f"color:{TEXT_GRAY}; font-size:10px; background:transparent; border:none;")
        lbl_ver = QtWidgets.QLabel("✅  Version 1.0.0")
        lbl_ver.setStyleSheet(
            "color:#22c55e; font-size:10px; background:transparent; border:none;")
        al.addWidget(lbl_about)
        al.addWidget(lbl_desc)
        al.addWidget(lbl_ver)
        sb_layout.addWidget(about_frame)

        root_h.addWidget(sidebar)
        root_h.addWidget(self.stack, 1)

        # Ouvrir sur Chiffrement symétrique (Affine) par défaut
        self._navigate(2, self._nav_buttons[2])

    def _navigate(self, index: int, active_btn: SidebarButton):
        self.stack.setCurrentIndex(index)
        for btn in self._nav_buttons:
            btn.setActive(btn is active_btn)
            btn.setChecked(btn is active_btn)


# ─────────────────────────────────────────────
#  ENTRÉE
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setFont(QtGui.QFont("Segoe UI", 10))
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())