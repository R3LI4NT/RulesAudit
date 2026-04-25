class ParticleSystem {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.packets = [];
        this.rules = [];
        this.connections = [];
        this.firewallGrid = [];
        
        this.init();
    }

    init() {
        this.canvas.id = 'particles-canvas';
        this.canvas.style.position = 'fixed';
        this.canvas.style.top = '0';
        this.canvas.style.left = '0';
        this.canvas.style.width = '100%';
        this.canvas.style.height = '100%';
        this.canvas.style.pointerEvents = 'none';
        this.canvas.style.zIndex = '1';
        
        const particlesDiv = document.getElementById('particles');
        if (particlesDiv) {
            particlesDiv.appendChild(this.canvas);
        } else {
            document.body.appendChild(this.canvas);
        }

        window.addEventListener('resize', () => this.resize());
        this.resize();
        this.createFirewallGrid();
        this.createRules();
        this.animate();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.createFirewallGrid();
    }

    createFirewallGrid() {
        this.firewallGrid = [];
        const cols = 20;
        const rows = 10;
        const cellWidth = this.canvas.width / cols;
        const cellHeight = this.canvas.height / rows;
        
        for (let i = 0; i < cols; i++) {
            for (let j = 0; j < rows; j++) {
                if (Math.random() > 0.7) {
                    this.firewallGrid.push({
                        x: i * cellWidth + cellWidth/2,
                        y: j * cellHeight + cellHeight/2,
                        status: Math.random() > 0.5 ? 'ALLOW' : 'DENY',
                        opacity: 0.1 + Math.random() * 0.2
                    });
                }
            }
        }
    }

    createRules() {
        const rulesList = [
            'ACCEPT tcp 80',
            'DROP tcp 22',
            'ACCEPT udp 53',
            'REJECT icmp',
            'ACCEPT tcp 443',
            'DROP all 0.0.0.0',
            'ACCEPT 192.168.1.*',
            'DENY 10.0.0.0/24',
            'FORWARD eth0',
            'MASQUERADE',
            'ACCEPT established',
            'DROP invalid'
        ];
        
        for (let i = 0; i < 8; i++) {
            this.rules.push({
                text: rulesList[Math.floor(Math.random() * rulesList.length)],
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                speed: 0.2 + Math.random() * 0.5,
                opacity: 0.1 + Math.random() * 0.3,
                direction: Math.random() > 0.5 ? 1 : -1
            });
        }
    }

    createPacket() {
        const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH'];
        const actions = ['ALLOW', 'DROP', 'REJECT', 'ACCEPT'];
        const isBlocked = Math.random() > 0.7;
        
        return {
            x: Math.random() * this.canvas.width,
            y: Math.random() * this.canvas.height,
            targetX: Math.random() * this.canvas.width,
            targetY: Math.random() * this.canvas.height,
            protocol: protocols[Math.floor(Math.random() * protocols.length)],
            action: isBlocked ? 'DROP' : 'ALLOW',
            port: Math.floor(Math.random() * 65535),
            size: Math.random() * 4 + 2,
            speed: 1 + Math.random() * 3,
            progress: 0,
            opacity: 0.8,
            blocked: isBlocked,
            color: isBlocked ? '#ff3333' : '#33ff33'
        };
    }

    drawFirewallGrid() {
        for (let cell of this.firewallGrid) {
            this.ctx.strokeStyle = `rgba(0, 255, 0, ${cell.opacity})`;
            this.ctx.lineWidth = 0.5;
            this.ctx.strokeRect(cell.x - 30, cell.y - 15, 60, 30);
            
            this.ctx.font = '10px monospace';
            this.ctx.fillStyle = cell.status === 'ALLOW' ? 
                `rgba(0, 255, 0, ${cell.opacity + 0.2})` : 
                `rgba(255, 50, 50, ${cell.opacity + 0.2})`;
            this.ctx.fillText(cell.status, cell.x - 20, cell.y);
        }
    }

    drawPackets() {
        if (Math.random() < 0.1) {
            this.packets.push(this.createPacket());
        }
        
        for (let i = this.packets.length - 1; i >= 0; i--) {
            const packet = this.packets[i];
            
            packet.progress += 0.01 * packet.speed;
            
            if (packet.progress >= 1) {
                this.packets.splice(i, 1);
                continue;
            }
            
            const x = packet.x + (packet.targetX - packet.x) * packet.progress;
            const y = packet.y + (packet.targetY - packet.y) * packet.progress;
            
            this.ctx.beginPath();
            this.ctx.strokeStyle = `rgba(255, 255, 255, 0.1)`;
            this.ctx.setLineDash([5, 5]);
            this.ctx.moveTo(packet.x, packet.y);
            this.ctx.lineTo(packet.targetX, packet.targetY);
            this.ctx.stroke();
            this.ctx.setLineDash([]);
            
            const gradient = this.ctx.createRadialGradient(x, y, 0, x, y, packet.size * 2);
            if (packet.blocked) {
                gradient.addColorStop(0, `rgba(255, 50, 50, ${packet.opacity})`);
                gradient.addColorStop(1, 'rgba(255, 0, 0, 0)');
            } else {
                gradient.addColorStop(0, `rgba(50, 255, 50, ${packet.opacity})`);
                gradient.addColorStop(1, 'rgba(0, 255, 0, 0)');
            }
            
            this.ctx.beginPath();
            this.ctx.arc(x, y, packet.size * 2, 0, Math.PI * 2);
            this.ctx.fillStyle = gradient;
            this.ctx.fill();
            
            this.ctx.font = '8px monospace';
            this.ctx.fillStyle = packet.blocked ? '#ff6666' : '#66ff66';
            this.ctx.fillText(`${packet.protocol}:${packet.port}`, x - 20, y - 10);
            this.ctx.fillText(packet.action, x - 15, y + 15);
        }
    }

    drawRules() {
        for (let rule of this.rules) {
            rule.y += rule.speed * rule.direction;
            
            if (rule.y > this.canvas.height || rule.y < 0) {
                rule.direction *= -1;
            }
            
            const scanEffect = Math.sin(Date.now() / 500 + rule.y) * 5;
            
            this.ctx.font = '14px monospace';
            this.ctx.fillStyle = `rgba(0, 255, 0, ${rule.opacity})`;
            this.ctx.fillText(`[RULE] ${rule.text}`, rule.x + scanEffect, rule.y);
            
            if (Math.random() < 0.01) {
                this.connections.push({
                    x1: rule.x,
                    y1: rule.y,
                    x2: Math.random() * this.canvas.width,
                    y2: Math.random() * this.canvas.height,
                    progress: 0,
                    opacity: 0.5
                });
            }
        }
    }

    drawConnections() {
        for (let i = this.connections.length - 1; i >= 0; i--) {
            const conn = this.connections[i];
            conn.progress += 0.02;
            conn.opacity -= 0.01;
            
            if (conn.progress >= 1 || conn.opacity <= 0) {
                this.connections.splice(i, 1);
                continue;
            }
            
            const x = conn.x1 + (conn.x2 - conn.x1) * conn.progress;
            const y = conn.y1 + (conn.y2 - conn.y1) * conn.progress;
            
            this.ctx.beginPath();
            this.ctx.strokeStyle = `rgba(0, 255, 0, ${conn.opacity})`;
            this.ctx.lineWidth = 1;
            this.ctx.moveTo(conn.x1, conn.y1);
            this.ctx.lineTo(x, y);
            this.ctx.stroke();
        }
    }

    drawLogs() {
        const time = Date.now() / 1000;
        const logY = (Math.sin(time * 2) * 0.3 + 0.5) * this.canvas.height;
        
        this.ctx.font = '10px monospace';
        this.ctx.fillStyle = 'rgba(0, 255, 0, 0.15)';
        
        const logs = [
            `[${new Date().toLocaleTimeString()}] FW: ACCEPT tcp 192.168.1.100:443`,
            `[${new Date().toLocaleTimeString()}] FW: DROP tcp 10.0.0.5:22 (unauthorized)`,
            `[${new Date().toLocaleTimeString()}] FW: ALLOW udp 8.8.8.8:53`,
            `[${new Date().toLocaleTimeString()}] FW: REJECT icmp from 172.16.1.1`,
            `[${new Date().toLocaleTimeString()}] FW: Rule #1042 matched - ACCEPT established`
        ];
        
        for (let i = 0; i < logs.length; i++) {
            this.ctx.fillText(logs[i], 20, logY + i * 15);
        }
    }

    draw() {
        this.ctx.fillStyle = 'rgba(0, 5, 0, 0.1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.drawFirewallGrid();
        this.drawRules();
        this.drawPackets();
        this.drawConnections();
        this.drawLogs();
        
        const time = Date.now() / 1000;
        const scanY = (Math.sin(time) * 0.5 + 0.5) * this.canvas.height;
        
        this.ctx.beginPath();
        this.ctx.strokeStyle = '#0f0';
        this.ctx.lineWidth = 1;
        this.ctx.setLineDash([20, 30]);
        this.ctx.moveTo(0, scanY);
        this.ctx.lineTo(this.canvas.width, scanY);
        this.ctx.stroke();
        
        this.ctx.setLineDash([]);
        this.ctx.font = 'bold 16px monospace';
        this.ctx.fillStyle = '#0f0';
        
    }

    animate() {
        this.draw();
        requestAnimationFrame(() => this.animate());
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ParticleSystem();
});