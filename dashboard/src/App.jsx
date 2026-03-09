import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = 'http://localhost:8000'; // Update this to your server IP if needed

function App() {
  const [alerts, setAlerts] = useState([]);
  const [settings, setSettings] = useState({ whitelist: [], threshold: 0.85 });
  const [newWhitelistIp, setNewWhitelistIp] = useState('');

  useEffect(() => {
    fetchAlerts();
    fetchSettings();
    const interval = setInterval(fetchAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/alerts`);
      setAlerts(response.data.alerts);
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  const fetchSettings = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/settings`);
      setSettings(response.data);
    } catch (error) {
      console.error("Error fetching settings:", error);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await axios.post(`${API_BASE_URL}/settings`, settings);
      alert("Settings saved successfully!");
    } catch (error) {
      console.error("Error saving settings:", error);
      alert("Failed to save settings.");
    }
  };

  const addToWhitelist = () => {
    if (newWhitelistIp && !settings.whitelist.includes(newWhitelistIp)) {
      setSettings({
        ...settings,
        whitelist: [...settings.whitelist, newWhitelistIp]
      });
      setNewWhitelistIp('');
    }
  };

  const removeFromWhitelist = (ip) => {
    setSettings({
      ...settings,
      whitelist: settings.whitelist.filter(item => item !== ip)
    });
  };

  return (
    <div className="container">
      <header>
        <h1 className="glitch" data-text="NEURALGUARD DASHBOARD">NEURALGUARD DASHBOARD</h1>
        <div className="status-bar">
          SYSTEM STATUS: <span className="active">ONLINE</span> | AI CORE: <span className="active">ACTIVE</span>
        </div>
      </header>

      <main>
        <section className="alerts-section">
          <h2>Recent Alerts</h2>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Win Size</th>
                  <th>Confidence</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.id} className={alert.verdict === 1 ? 'danger' : ''}>
                    <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                    <td>{alert.src_ip}</td>
                    <td>{alert.dest_ip}</td>
                    <td>{alert.window_size}</td>
                    <td>{(alert.score * 100).toFixed(2)}%</td>
                    <td>{alert.verdict === 1 ? 'MALICIOUS' : 'BENIGN'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="settings-panel">
          <h2>Configuration Control</h2>
          <div className="settings-grid">
            <div className="setting-item">
              <label>AI Detection Threshold: <span>{settings.threshold}</span></label>
              <input 
                type="range" 
                min="0.0" 
                max="1.0" 
                step="0.01" 
                value={settings.threshold} 
                onChange={(e) => setSettings({...settings, threshold: parseFloat(e.target.value)})}
              />
              <p className="hint">Lower is more aggressive; Higher reduces false positives.</p>
            </div>

            <div className="setting-item">
              <label>Network Whitelist</label>
              <div className="whitelist-input">
                <input 
                  type="text" 
                  placeholder="Enter IP to whitelist..." 
                  value={newWhitelistIp}
                  onChange={(e) => setNewWhitelistIp(e.target.value)}
                />
                <button onClick={addToWhitelist}>ADD</button>
              </div>
              <div className="whitelist-tags">
                {settings.whitelist.map(ip => (
                  <span key={ip} className="tag">
                    {ip} <button onClick={() => removeFromWhitelist(ip)}>x</button>
                  </span>
                ))}
              </div>
            </div>
          </div>
          <button className="save-btn" onClick={handleSaveSettings}>SAVE SETTINGS</button>
        </section>
      </main>
    </div>
  );
}

export default App;
