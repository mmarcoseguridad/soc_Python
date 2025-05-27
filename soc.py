import os
import re
import time
import json
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from collections import Counter, defaultdict

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='soc_monitor.log'
)
logger = logging.getLogger('SOC')

class SecurityOperationsCenter:
    def __init__(self, config_file='soc_config.json'):
        """Inicializa el SOC con la configuración desde un archivo JSON"""
        self.config = self._load_config(config_file)
        self.alert_count = 0
        self.ip_attempts = defaultdict(int)
        self.known_threats = self._load_threat_intelligence()
        logger.info("SOC inicializado correctamente")

    def _load_config(self, config_file):
        """Carga la configuración desde un archivo JSON"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                # Configuración por defecto
                default_config = {
                    "log_files": ["/var/log/auth.log", "/var/log/apache2/access.log"],
                    "alert_threshold": 5,
                    "scan_interval": 60,
                    "email_alerts": {
                        "enabled": False,
                        "smtp_server": "smtp.example.com",
                        "smtp_port": 587,
                        "username": "alert@example.com",
                        "password": "password",
                        "recipients": ["admin@example.com"]
                    },
                    "patterns": {
                        "failed_login": "Failed password for .* from (\\d+\\.\\d+\\.\\d+\\.\\d+)",
                        "web_attack": ".*(?:union\\+select|exec\\(|eval\\(|<script>).*"
                    }
                }
                # Guardar la configuración por defecto
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                logger.info(f"Creado archivo de configuración por defecto: {config_file}")
                return default_config
        except Exception as e:
            logger.error(f"Error al cargar la configuración: {str(e)}")
            raise

    def _load_threat_intelligence(self):
        """Carga la base de datos de inteligencia de amenazas"""
        try:
            if os.path.exists('threat_intel.json'):
                with open('threat_intel.json', 'r') as f:
                    return json.load(f)
            else:
                # Base de datos de amenazas básica
                threat_intel = {
                    "malicious_ips": [
                        "192.168.1.100",  # Ejemplo
                        "10.0.0.99"       # Ejemplo
                    ],
                    "attack_signatures": [
                        "union select",
                        "exec(",
                        "eval(",
                        "<script>"
                    ]
                }
                # Guardar la base de datos
                with open('threat_intel.json', 'w') as f:
                    json.dump(threat_intel, f, indent=4)
                logger.info("Creada base de datos de inteligencia de amenazas por defecto")
                return threat_intel
        except Exception as e:
            logger.error(f"Error al cargar la inteligencia de amenazas: {str(e)}")
            return {"malicious_ips": [], "attack_signatures": []}

    def monitor_logs(self):
        """Monitoriza los archivos de log en busca de patrones sospechosos"""
        logger.info("Iniciando monitorización de logs")

        while True:
            try:
                for log_file in self.config["log_files"]:
                    if os.path.exists(log_file):
                        self._analyze_log(log_file)
                    else:
                        logger.warning(f"Archivo de log no encontrado: {log_file}")

                # Esperar antes del siguiente escaneo
                time.sleep(self.config["scan_interval"])
            except KeyboardInterrupt:
                logger.info("Monitorización detenida por el usuario")
                break
            except Exception as e:
                logger.error(f"Error durante la monitorización: {str(e)}")
                time.sleep(10)  # Esperar antes de reintentar

    def _analyze_log(self, log_file):
        """Analiza un archivo de log en busca de patrones sospechosos"""
        try:
            # Leer las últimas líneas del archivo
            with open(log_file, 'r') as f:
                # Mover al final del archivo y luego retroceder para leer las últimas líneas
                f.seek(0, 2)
                file_size = f.tell()
                # Leer los últimos 4KB o todo el archivo si es más pequeño
                read_size = min(4096, file_size)
                f.seek(max(0, file_size - read_size))
                lines = f.readlines()

            # Analizar cada línea
            for line in lines:
                self._check_patterns(line, log_file)

        except Exception as e:
            logger.error(f"Error al analizar el log {log_file}: {str(e)}")

    def _check_patterns(self, line, log_file):
        """Comprueba si una línea de log coincide con patrones sospechosos"""
        # Comprobar intentos de login fallidos
        if "failed_login" in self.config["patterns"]:
            pattern = self.config["patterns"]["failed_login"]
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                self._handle_failed_login(ip, line)

        # Comprobar ataques web
        if "web_attack" in self.config["patterns"]:
            pattern = self.config["patterns"]["web_attack"]
            if re.search(pattern, line, re.IGNORECASE):
                self._generate_alert("Posible ataque web detectado", line, log_file, "HIGH")

        # Comprobar IPs maliciosas conocidas
        for ip in self.known_threats["malicious_ips"]:
            if ip in line:
                self._generate_alert(f"Actividad desde IP maliciosa conocida: {ip}",
                                    line, log_file, "CRITICAL")

    def _handle_failed_login(self, ip, log_line):
        """Gestiona los intentos de login fallidos desde una IP"""
        self.ip_attempts[ip] += 1

        # Si supera el umbral, generar alerta
        if self.ip_attempts[ip] >= self.config["alert_threshold"]:
            self._generate_alert(
                f"Posible ataque de fuerza bruta desde {ip} - {self.ip_attempts[ip]} intentos",
                log_line, "auth.log", "MEDIUM"
            )
            # Resetear contador para no generar alertas continuas
            self.ip_attempts[ip] = 0

    def _generate_alert(self, message, log_line, source, severity):
        """Genera una alerta de seguridad"""
        self.alert_count += 1
        alert_id = f"ALERT-{datetime.now().strftime('%Y%m%d')}-{self.alert_count}"

        alert = {
            "id": alert_id,
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "source": source,
            "severity": severity,
            "log_data": log_line.strip()
        }

        # Registrar la alerta
        logger.warning(f"ALERTA {alert_id}: {message} [{severity}]")

        # Guardar la alerta en un archivo JSON
        self._save_alert(alert)

        # Enviar alerta por email si está configurado
        if self.config["email_alerts"]["enabled"]:
            self._send_email_alert(alert)

    def _save_alert(self, alert):
        """Guarda una alerta en el archivo de alertas"""
        try:
            alerts = []
            if os.path.exists('alerts.json'):
                with open('alerts.json', 'r') as f:
                    alerts = json.load(f)

            alerts.append(alert)

            with open('alerts.json', 'w') as f:
                json.dump(alerts, f, indent=4)

        except Exception as e:
            logger.error(f"Error al guardar la alerta: {str(e)}")

    def _send_email_alert(self, alert):
        """Envía una alerta por email"""
        try:
            config = self.config["email_alerts"]

            # Crear el mensaje
            subject = f"[SOC ALERT] {alert['severity']}: {alert['message']}"
            body = f"""
            Alerta de Seguridad: {alert['id']}
            -----------------------------
            Severidad: {alert['severity']}
            Fecha/Hora: {alert['timestamp']}
            Fuente: {alert['source']}

            Mensaje: {alert['message']}

            Datos del log:
            {alert['log_data']}

            Este mensaje ha sido generado automáticamente por el SOC.
            """

            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = config['username']
            msg['To'] = ', '.join(config['recipients'])

            # Enviar el email
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                server.starttls()
                server.login(config['username'], config['password'])
                server.send_message(msg)

            logger.info(f"Alerta enviada por email: {alert['id']}")

        except Exception as e:
            logger.error(f"Error al enviar alerta por email: {str(e)}")

    def generate_report(self):
        """Genera un informe de seguridad con las alertas recientes"""
        try:
            if not os.path.exists('alerts.json'):
                logger.warning("No hay alertas para generar el informe")
                return "No hay alertas registradas"

            with open('alerts.json', 'r') as f:
                alerts = json.load(f)

            # Filtrar alertas de las últimas 24 horas
            now = datetime.now()
            recent_alerts = [
                a for a in alerts
                if (now - datetime.fromisoformat(a['timestamp'])).total_seconds() < 86400
            ]

            # Contar por severidad
            severity_counts = Counter(a['severity'] for a in recent_alerts)

            # Generar informe
            report = f"""
            INFORME DE SEGURIDAD - {now.strftime('%Y-%m-%d %H:%M:%S')}
            =====================================================

            Resumen de alertas (últimas 24 horas):
            - Total: {len(recent_alerts)}
            - Críticas: {severity_counts.get('CRITICAL', 0)}
            - Altas: {severity_counts.get('HIGH', 0)}
            - Medias: {severity_counts.get('MEDIUM', 0)}
            - Bajas: {severity_counts.get('LOW', 0)}

            Últimas 5 alertas:
            """

            # Añadir las últimas 5 alertas al informe
            for alert in recent_alerts[-5:]:
                report += f"""
            * {alert['timestamp']} - {alert['severity']} - {alert['message']}
              Fuente: {alert['source']}
            """

            # Guardar el informe
            report_file = f"security_report_{now.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, 'w') as f:
                f.write(report)

            logger.info(f"Informe de seguridad generado: {report_file}")
            return report

        except Exception as e:
            logger.error(f"Error al generar el informe: {str(e)}")
            return f"Error al generar el informe: {str(e)}"

# Función principal
def main():
    print("Iniciando Security Operations Center (SOC)...")
    soc = SecurityOperationsCenter()

    try:
        # Iniciar monitorización
        soc.monitor_logs()
    except KeyboardInterrupt:
        print("\nDeteniendo SOC...")
    finally:
        # Generar informe final
        print("Generando informe final...")
        report = soc.generate_report()
        print("SOC detenido. Informe final generado.")

if __name__ == "__main__":
    main()
