import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QSpinBox, QComboBox, QStackedWidget
)
from PyQt6.QtCore import Qt
import base64

class CesarCipherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cifrador y Codificador")
        self.setGeometry(100, 100, 600, 400)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2e2e2e;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 14px;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #4a4a4a;
                border: 1px solid #666666;
                color: #c0c0c0;
                padding: 5px;
                border-radius: 5px;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #007acc;
                border: none;
                width: 20px;
            }
            QSpinBox::up-arrow, QSpinBox::down-arrow {
                background-color: #007acc;
                border: none;
            }
            QComboBox::drop-down {
                background-color: #4a4a4a;
                border: 1px solid #666666;
                border-radius: 5px;
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        mode_layout = QHBoxLayout()
        mode_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        mode_label = QLabel("Seleccionar modo:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Cifrado César", "ROT13", "Base64"])
        self.mode_combo.currentIndexChanged.connect(self.update_mode)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        main_layout.addLayout(mode_layout)

        self.stacked_widget = QStackedWidget()
        
        cesar_widget = QWidget()
        cesar_layout = QVBoxLayout(cesar_widget)

        shift_layout = QHBoxLayout()
        shift_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        shift_label = QLabel("Desplazamiento:")
        self.shift_spinbox = QSpinBox()
        self.shift_spinbox.setRange(0, 25)
        self.shift_spinbox.setValue(3)
        self.shift_spinbox.setFixedSize(50, 30)
        self.shift_spinbox.setStyleSheet("text-align: center;")
        self.shift_spinbox.valueChanged.connect(self.update_cipher)
        shift_layout.addWidget(shift_label)
        shift_layout.addWidget(self.shift_spinbox)
        cesar_layout.addLayout(shift_layout)

        cesar_layout.addWidget(QLabel("Texto a encriptar:"))
        self.input_encrypt = QLineEdit()
        self.input_encrypt.textChanged.connect(self.update_cipher)
        cesar_layout.addWidget(self.input_encrypt)
        
        cesar_layout.addWidget(QLabel("Texto encriptado:"))
        self.output_encrypt = QLineEdit()
        self.output_encrypt.setReadOnly(True)
        cesar_layout.addWidget(self.output_encrypt)

        cesar_layout.addSpacing(20)
        cesar_layout.addWidget(QLabel("Texto a desencriptar:"))
        self.input_decrypt = QLineEdit()
        self.input_decrypt.textChanged.connect(self.update_decipher)
        cesar_layout.addWidget(self.input_decrypt)

        cesar_layout.addWidget(QLabel("Texto desencriptado:"))
        self.output_decrypt = QLineEdit()
        self.output_decrypt.setReadOnly(True)
        cesar_layout.addWidget(self.output_decrypt)
        
        self.stacked_widget.addWidget(cesar_widget)


        base64_widget = QWidget()
        base64_layout = QVBoxLayout(base64_widget)

        base64_layout.addWidget(QLabel("Texto a codificar:"))
        self.input_encode_base64 = QLineEdit()
        self.input_encode_base64.textChanged.connect(self.update_base64)
        base64_layout.addWidget(self.input_encode_base64)
        
        base64_layout.addWidget(QLabel("Texto codificado:"))
        self.output_encode_base64 = QLineEdit()
        self.output_encode_base64.setReadOnly(True)
        base64_layout.addWidget(self.output_encode_base64)
        
        base64_layout.addSpacing(20)

        base64_layout.addWidget(QLabel("Texto a decodificar:"))
        self.input_decode_base64 = QLineEdit()
        self.input_decode_base64.textChanged.connect(self.update_base64)
        base64_layout.addWidget(self.input_decode_base64)
        
        base64_layout.addWidget(QLabel("Texto decodificado:"))
        self.output_decode_base64 = QLineEdit()
        self.output_decode_base64.setReadOnly(True)
        base64_layout.addWidget(self.output_decode_base64)
        
        self.stacked_widget.addWidget(base64_widget)
        
        main_layout.addWidget(self.stacked_widget)
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        author_label = QLabel("by: Ars byte")
        author_label.setFont(self.font())
        author_label.setStyleSheet("color: #888888; font-size: 10px;")
        footer_layout.addWidget(author_label)
        main_layout.addLayout(footer_layout)
        
    def update_mode(self, index):
        self.stacked_widget.setCurrentIndex(index)
        if index == 0:
            self.shift_spinbox.show()
            self.shift_spinbox.setValue(self.shift_spinbox.value())
        elif index == 1:
            self.shift_spinbox.hide()
            self.shift_spinbox.setValue(13)
            self.update_cipher()
        elif index == 2:
            self.shift_spinbox.hide()
            self.update_base64()

    def update_cipher(self):
        mode_index = self.mode_combo.currentIndex()
        if mode_index == 0:
            shift = self.shift_spinbox.value()
        elif mode_index == 1:
            shift = 13
        else:
            return
            
        text = self.input_encrypt.text()
        encrypted_text = self._cesar_cipher(text, shift)
        self.output_encrypt.setText(encrypted_text)

    def update_decipher(self):
        mode_index = self.mode_combo.currentIndex()
        if mode_index == 0:
            shift = self.shift_spinbox.value()
        elif mode_index == 1:
            shift = 13
        else:
            return
            
        text = self.input_decrypt.text()
        decrypted_text = self._cesar_cipher(text, -shift)
        self.output_decrypt.setText(decrypted_text)
    
    def _cesar_cipher(self, text, shift):
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                new_char_code = ord('a') + (ord(char) - ord('a') + shift) % 26
                result += chr(new_char_code)
            elif 'A' <= char <= 'Z':
                new_char_code = ord('A') + (ord(char) - ord('A') + shift) % 26
                result += chr(new_char_code)
            else:
                result += char
        return result

    def update_base64(self):
        text_to_encode = self.input_encode_base64.text()
        encoded_text = self._base64_encode(text_to_encode)
        self.output_encode_base64.setText(encoded_text)

        text_to_decode = self.input_decode_base64.text()
        decoded_text = self._base64_decode(text_to_decode)
        self.output_decode_base64.setText(decoded_text)
        
    def _base64_encode(self, text):
        try:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            return encoded_bytes.decode('utf-8')
        except Exception:
            return "Error de codificación"
            
    def _base64_decode(self, text):
        try:
            decoded_bytes = base64.b64decode(text.encode('utf-8'))
            return decoded_bytes.decode('utf-8')
        except Exception:
            return "Error de decodificación"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CesarCipherApp()
    window.show()
    sys.exit(app.exec())
