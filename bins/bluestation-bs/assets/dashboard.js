(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = { snapshot: null, history: [], runId: null, lastResponse: 0, activeTab: 'overview', page: 0, selectedTerminal: null, fetching: false, charts: {} };
  const slotTypes = [
    { key: 'control', label: 'Control', color: '#0d6efd' },
    { key: 'voice', label: 'Voice', color: '#fd7e14' },
    { key: 'packet', label: 'Packet data', color: '#9561e2' },
    { key: 'free', label: 'Free', color: '#8a9097' },
  ];
  const slotChartTypes = slotTypes.filter(type => type.key !== 'free');
  const frameSubslots = { 3: 1, 4: 2, 5: 3, 6: 4, 7: 5, 8: 6, 9: 8, 10: 10, 11: 12, 12: 16, 13: 20, 14: 24, 15: 32 };
  const fmt = (v, digits = 0) => v == null || !Number.isFinite(Number(v)) ? '—' : Number(v).toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits });
  const pct = (v, digits = 0) => v == null ? '—' : `${fmt(v, digits)}%`;
  const byte = (v, rate = false) => {
    if (v == null || !Number.isFinite(Number(v))) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0; let n = Number(v);
    while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
    return `${fmt(n, n < 10 && i ? 1 : 0)} ${units[i]}${rate ? '/s' : ''}`;
  };
  const when = ms => ms == null || !ms ? '—' : new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
  const age = ms => {
    if (ms == null || !ms) return 'Never';
    const seconds = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };
  const duration = sec => {
    if (sec == null) return '—';
    const days = Math.floor(sec / 86400), hours = Math.floor(sec % 86400 / 3600), minutes = Math.floor(sec % 3600 / 60);
    return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
  };
  const setText = (id, value) => { const el = $(id); if (el) el.textContent = value == null ? '—' : String(value); };
  const setTone = (id, tone) => {
    const el = $(id); if (!el) return;
    el.dataset.tone = tone;
    if (el.classList.contains('badge')) {
      el.classList.remove('text-bg-success', 'text-bg-warning', 'text-bg-danger', 'text-bg-secondary');
      el.classList.add(`text-bg-${{ good: 'success', warn: 'warning', bad: 'danger', muted: 'secondary' }[tone] || 'secondary'}`);
    }
  };
  const cell = (row, value, className) => { const td = document.createElement('td'); td.textContent = String(value ?? '—'); if (className) td.className = className; row.appendChild(td); return td; };
  const property = (label, value) => {
    const row = document.createElement('div'); row.className = 'property-row';
    const key = document.createElement('span'); key.textContent = label;
    const val = document.createElement('strong'); val.textContent = value ?? '—';
    row.append(key, val); return row;
  };
  const replace = (id, nodes) => { const target = $(id); target.replaceChildren(...nodes); };
  const setConnectionStatus = message => {
    const status = $('connection-status');
    status.hidden = !message;
    status.textContent = message || '';
  };
  const terminalModal = new bootstrap.Modal($('terminal-modal'));
  $('terminal-modal').addEventListener('hidden.bs.modal', () => { state.selectedTerminal = null; });
  const sensorDisplayName = name => name.replace(/[_-]+/g, ' ').replace(/\b(cpu|adc|rp\d+)\b/gi, match => match.toUpperCase());

  function selectTab(name, focus = false) {
    state.activeTab = name;
    for (const tab of document.querySelectorAll('[data-tab]')) {
      const selected = tab.dataset.tab === name;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      if (focus && selected) tab.focus();
    }
    for (const view of document.querySelectorAll('.view')) {
      const selected = view.id === `view-${name}`;
      view.hidden = !selected;
      view.classList.toggle('active', selected);
    }
    for (const chart of Object.values(state.charts)) chart.resize();
  }
  for (const tab of document.querySelectorAll('[data-tab]')) {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...document.querySelectorAll('[data-tab]')]; const index = tabs.indexOf(tab);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      selectTab(tabs[next].dataset.tab, true);
    });
  }

  function theme() {
    const dark = document.documentElement.dataset.bsTheme === 'dark';
    const next = dark ? 'light' : 'dark'; document.documentElement.dataset.bsTheme = next;
    try { localStorage.setItem('bs-theme', next); } catch (_) {}
    styleCharts();
  }
  $('theme-toggle').addEventListener('click', theme);

  function lineChart(id, datasets, percent = false) {
    const canvas = $(id);
    const chart = new Chart(canvas, {
      type: 'line',
      data: { labels: [], datasets: datasets.map((d, index) => ({
        label: d.label, data: [], borderColor: d.color, backgroundColor: d.color,
        borderWidth: index === 0 ? 2 : 1.7, tension: .15, pointRadius: id === 'chart-swmi' ? 2 : 0,
        pointHoverRadius: 4, spanGaps: false, fill: false,
      })) },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false, normalized: true,
        interaction: { intersect: false, mode: 'index' },
        plugins: { legend: { position: 'bottom', align: 'start', labels: { boxWidth: 10, boxHeight: 2, padding: 16 } }, tooltip: { callbacks: { label: context => id === 'chart-temperature'
          ? `${sensorDisplayName(context.dataset.sensorName)}: ${fmt(context.parsed.y, 1)} °C`
          : `${context.dataset.label}: ${fmt(context.parsed.y, 1)}${percent ? '%' : ''}` } } },
        scales: { x: { ticks: { maxTicksLimit: 6, maxRotation: 0 }, grid: { display: false } }, y: { beginAtZero: true, suggestedMax: percent ? 100 : undefined, ticks: { maxTicksLimit: 5, callback: percent ? v => `${v}%` : undefined }, border: { display: false } } },
      },
    });
    state.charts[id] = chart;
    return chart;
  }
  lineChart('chart-overview', [{ label: 'CPU', color: '#0d6efd' }, { label: 'RAM', color: '#198754' }], true);
  lineChart('chart-system', [{ label: 'CPU', color: '#0d6efd' }, { label: 'RAM', color: '#198754' }], true);
  lineChart('chart-temperature', []);
  lineChart('chart-network', [{ label: 'RX · KB/s', color: '#0d6efd' }, { label: 'TX · KB/s', color: '#198754' }]);
  lineChart('chart-ra', [{ label: 'EWMA', color: '#0d6efd' }, { label: 'Low', color: '#198754' }, { label: 'High', color: '#ffc107' }]);
  lineChart('chart-swmi', [{ label: 'WebSocket RTT · ms', color: '#0d6efd' }]);
  const slotChart = lineChart('chart-cell-slots', slotChartTypes);
  slotChart.data.datasets.forEach((dataset, index) => {
    const hex = slotChartTypes[index].color;
    const rgb = [1, 3, 5].map(start => parseInt(hex.slice(start, start + 2), 16));
    dataset.borderColor = dataset.backgroundColor = `rgba(${rgb.join(',')},0.65)`;
    dataset.borderDash = [[], [7, 3], [2, 3]][index];
    dataset.borderWidth = 2;
    dataset.stepped = true; dataset.tension = 0;
  });
  slotChart.options.scales.y.max = 4;
  slotChart.options.scales.y.ticks.stepSize = 1;
  slotChart.options.scales.y.title = { display: true, text: 'Timeslots' };
  slotChart.options.plugins.tooltip.callbacks.label = context => `${context.dataset.label}: ${fmt(context.parsed.y)}`;

  function styleCharts() {
    const styles = getComputedStyle(document.documentElement);
    const text = styles.getPropertyValue('--bs-secondary-color').trim();
    const grid = styles.getPropertyValue('--bs-border-color').trim();
    for (const chart of Object.values(state.charts)) {
      chart.options.scales.x.ticks.color = text; chart.options.scales.y.ticks.color = text;
      chart.options.scales.y.grid.color = grid; chart.options.plugins.legend.labels.color = text;
      if (chart.options.scales.y.title) chart.options.scales.y.title.color = text;
      chart.update('none');
    }
  }
  styleCharts();

  function drawCharts() {
    const points = state.history;
    const labels = points.map(p => new Date(p.at_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    const update = (id, datasets) => {
      const chart = state.charts[id]; chart.data.labels = labels;
      datasets.forEach((values, i) => { chart.data.datasets[i].data = values; });
      chart.update('none');
    };
    const cpu = points.map(p => p.cpu_percent), ram = points.map(p => p.ram_percent);
    update('chart-overview', [cpu, ram]); update('chart-system', [cpu, ram]);
    const temperatureChart = state.charts['chart-temperature'];
    const currentTemperatures = new Map((state.snapshot?.system?.temperatures || []).map(sensor => [sensor.label, sensor.celsius]));
    const sensorNames = [...new Set(points.flatMap(point => (point.temperatures || []).map(sensor => sensor.label)))].slice(0, 32);
    const sensorColors = ['#0d6efd', '#fd7e14', '#198754', '#6f42c1', '#d63384', '#20c997', '#dc3545', '#0dcaf0'];
    const previous = new Map(temperatureChart.data.datasets.map(dataset => [dataset.sensorName, dataset]));
    temperatureChart.data.labels = labels;
    temperatureChart.data.datasets = sensorNames.map((name, index) => {
      const old = previous.get(name);
      const current = currentTemperatures.get(name);
      return {
        sensorName: name,
        label: `${sensorDisplayName(name)} · ${current == null ? '—' : `${fmt(current, 1)} °C`}`,
        data: points.map(point => point.temperatures?.find(sensor => sensor.label === name)?.celsius ?? null),
        borderColor: sensorColors[index % sensorColors.length],
        backgroundColor: sensorColors[index % sensorColors.length],
        borderWidth: 2, tension: .15, pointRadius: 0, pointHoverRadius: 4,
        spanGaps: false, fill: false, hidden: old?.hidden ?? false,
      };
    });
    temperatureChart.update('none');
    const interfaceName = $('network-select').value;
    const rates = points.map(p => interfaceName === '__all' ? p : p.interfaces?.find(n => n.name === interfaceName));
    update('chart-network', [rates.map(n => n?.rx_bytes_per_sec == null ? null : n.rx_bytes_per_sec / 1000), rates.map(n => n?.tx_bytes_per_sec == null ? null : n.tx_bytes_per_sec / 1000)]);
    const ra = state.snapshot?.radio?.ra;
    update('chart-ra', [points.map(p => p.ra_score), points.map(() => ra?.low_threshold ?? null), points.map(() => ra?.high_threshold ?? null)]);
    update('chart-swmi', [points.map(p => p.rtt_ms)]);
    update('chart-cell-slots', slotChartTypes.map(type => points.map(p => p.slots?.[type.key] ?? null)));
  }

  function renderSlots(id, radio) {
    replace(id, radio.timeslots.map((name, i) => {
      const item = document.createElement('div');
      const type = slotTypes.find(type => type.label === name)?.key || 'free';
      item.className = `slot slot--${type}`;
      const label = document.createElement('span'); label.textContent = `TS${i + 1}`;
      const value = document.createElement('strong'); value.textContent = radio.measured_at_ms ? name : '—';
      item.append(label, value); return item;
    }));
  }

  function renderCell(s) {
    const c = s.radio.cell;
    const yes = value => value == null ? '—' : value ? 'Yes' : 'No';
    const mhz = value => value == null ? '—' : `${fmt(value / 1000000, 6)} MHz`;
    for (const [id, value] of Object.entries({ mcc: c?.mcc, mnc: c?.mnc, la: c?.location_area, hf: c?.time.h, mf: c?.time.m, frame: c?.time.f, ts: c?.time.t })) setText(`cell-${id}`, value ?? '—');
    setText('cell-radio', s.radio.radio_tx_enabled === false ? 'TX disabled' : s.radio.radio_tx_active ? 'Transmitting' : 'Inactive');
    setTone('cell-radio', s.radio.radio_tx_active ? 'good' : 'muted');
    replace('cell-identity-properties', [
      property('Colour code', fmt(c?.colour_code)),
      property('System code', c ? ['TETRA V+D · ed. 1, no security', 'TETRA V+D · ed. 1 + security', 'TETRA V+D · v2', 'TETRA V+D · v3'][c.system_code] || `Reserved (${c.system_code})` : '—'),
      property('Subscriber classes', !c ? '—' : c.subscriber_class === 65535 ? 'All classes' : c.subscriber_class === 0 ? 'None' : Array.from({ length: 16 }, (_, i) => i + 1).filter(cls => c.subscriber_class & (1 << (16 - cls))).join(', ')),
    ]);
    const frequencies = c?.frequencies_hz;
    replace('cell-carrier-properties', [
      property('Downlink', mhz(frequencies?.[0])), property('Uplink', mhz(frequencies?.[1])),
      property('Frequency band', c ? `${c.frequency_band * 100} MHz base` : '—'),
      property('Main carrier', fmt(c?.main_carrier)),
      property('Carrier offset', c ? `${c.offset_hz > 0 ? '+' : ''}${fmt(c.offset_hz / 1000, 2)} kHz` : '—'),
      property('Duplex spacing', frequencies ? `${fmt(Math.abs(frequencies[0] - frequencies[1]) / 1000000, 4)} MHz` : '—'),
      property('Uplink direction', c ? c.reverse_operation ? 'Above downlink (reverse)' : 'Below downlink (normal)' : '—'),
      property('Sharing mode', c ? ['Continuous transmission', 'Carrier sharing', 'MCCH sharing', 'Traffic carrier sharing'][c.sharing_mode] : '—'),
    ]);
    const timeoutSlots = c ? 144 * c.radio_dl_timeout : null;
    replace('cell-sysinfo-properties', [
      property('Maximum MS transmit power', !c ? '—' : c.ms_txpwr_max_cell ? `${10 + c.ms_txpwr_max_cell * 5} dBm` : 'Reserved'),
      property('Minimum RX access level', c ? `${-125 + 5 * c.rxlev_access_min} dBm` : '—'),
      property('Access parameter', c ? `${-53 + 2 * c.access_parameter} dBm` : '—'),
      property('Radio downlink timeout', !c ? '—' : !timeoutSlots ? 'Disabled' : `${timeoutSlots} timeslots · ${fmt(timeoutSlots / 4 * 17 / 300, 2)} s`),
      property('Secondary control channels', fmt(c?.secondary_control_channels)),
      property('Dynamic random access', c ? yes(s.radio.ra.dynamic) : '—'),
    ]);
    renderSlots('cell-slots', s.radio);
    setText('cell-slots-used', c ? `${s.radio.timeslots.filter(slot => slot !== 'Free').length} / 4 in use` : '—');
    replace('cell-services', (c?.services || []).map(([label, enabled]) => {
      const badge = document.createElement('span');
      badge.className = `badge ${enabled ? 'text-bg-success' : 'text-bg-secondary'}`;
      badge.textContent = `${label} · ${enabled ? 'Yes' : 'No'}`;
      return badge;
    }));
  }

  function renderOverview(s) {
    const radio = s.radio, swmi = s.swmi, system = s.system;
    setText('overview-swmi', swmi.phase || 'Connecting'); setTone('overview-swmi', radio.network_connected ? 'good' : swmi.connected ? 'warn' : 'bad');
    setText('overview-ping', swmi.rtt_ms == null || !swmi.connected ? 'Ping unavailable' : `${fmt(swmi.rtt_ms, 1)} ms`);
    setText('overview-radio', radio.radio_tx_enabled === false ? 'TX disabled' : radio.radio_tx_active ? 'Transmitting' : radio.radio_tx_allowed ? 'Ready' : 'Inactive');
    setTone('overview-radio', radio.radio_tx_active ? 'good' : radio.radio_tx_allowed ? 'warn' : 'muted');
    setText('overview-radio-detail', !radio.network_connected && radio.provisioned_once ? 'Local fallback' : radio.network_connected ? 'Central connection' : 'Awaiting SwMI');
    setText('overview-ra', radio.ra.load || 'Starting'); setTone('overview-ra', radio.ra.load === 'Heavy' ? 'bad' : radio.ra.load === 'Contention' ? 'warn' : 'good');
    setText('overview-ra-mode', radio.measured_at_ms ? (radio.ra.dynamic ? 'Dynamic' : 'Static') : 'Awaiting radio');
    setText('overview-terminals', radio.measured_at_ms ? fmt(radio.terminals.length) : '—');
    const pdpCount = radio.terminals.filter(t => t.pdp?.session).length;
    setText('overview-pdp', radio.measured_at_ms ? `${pdpCount} PDP ${pdpCount === 1 ? 'context' : 'contexts'}` : '—');
    setText('tab-terminal-count', radio.terminals.length);
    setText('overview-cpu', pct(system.cpu_percent, 1));
    setText('overview-ram', `RAM ${pct(system.ram_total_bytes ? system.ram_used_bytes * 100 / system.ram_total_bytes : null)}`);
    setText('overview-temperature', system.cpu_temperature_c == null ? 'Unavailable' : `${fmt(system.cpu_temperature_c, 1)} °C`);
    const rx = system.network.reduce((sum, n) => sum + (n.rx_bytes_per_sec || 0), 0), tx = system.network.reduce((sum, n) => sum + (n.tx_bytes_per_sec || 0), 0);
    setText('overview-network', `${byte(rx, true)} / ${byte(tx, true)}`);
    renderSlots('overview-slots', radio);
    const raAvailable = !!radio.measured_at_ms;
    const ra = radio.ra;
    setText('overview-ra-imm', fmt(raAvailable ? ra.current.imm : null));
    setText('overview-ra-wt', fmt(raAvailable ? ra.current.wt : null));
    setText('overview-ra-nu', fmt(raAvailable ? ra.current.nu : null));
    setText('overview-ra-frame', raAvailable ? raValue('frame_len', ra.current.frame_len) : '—');
    renderOverviewTerminals(radio.terminals, raAvailable);
  }

  function renderSystem(s) {
    const data = s.system;
    setText('system-cpu', pct(data.cpu_percent, 1));
    setText('system-ram', `${byte(data.ram_used_bytes)} / ${byte(data.ram_total_bytes)}`);
    setText('system-process-cpu', pct(data.process_cpu_percent, 1));
    setText('system-process-ram', byte(data.process_ram_bytes));
    const cpu = Math.max(0, Math.min(100, data.cpu_percent || 0));
    const ram = data.ram_total_bytes ? Math.max(0, Math.min(100, 100 * data.ram_used_bytes / data.ram_total_bytes)) : 0;
    $('cpu-bar').style.width = `${cpu}%`; $('ram-bar').style.width = `${ram}%`;
    $('cpu-bar').parentElement.setAttribute('aria-valuenow', fmt(cpu));
    $('ram-bar').parentElement.setAttribute('aria-valuenow', fmt(ram));
    replace('platform-properties', [
      property('Hostname', data.hostname), property('Hardware', data.model), property('CPU', data.cpu_model),
      property('CPU cores', data.cpu_cores || null), property('Linux', data.linux_version),
      property('Kernel', data.kernel_version), property('Architecture', data.architecture),
      property('Host uptime', duration(data.host_uptime_sec)), property('BS uptime', duration(data.process_uptime_sec)),
    ]);
    const select = $('network-select'); const old = select.value;
    const names = ['__all', ...data.network.map(n => n.name)];
    if (select.options.length !== names.length || names.some((name, i) => select.options[i]?.value !== name)) {
      select.replaceChildren(...names.map(name => { const option = document.createElement('option'); option.value = name; option.textContent = name === '__all' ? 'All interfaces' : name; return option; }));
      select.value = names.includes(old) ? old : '__all';
    }
    replace('network-rows', data.network.map(n => {
      const tr = document.createElement('tr');
      cell(tr, n.name); cell(tr, byte(n.rx_bytes_per_sec, true), 'text-end'); cell(tr, byte(n.tx_bytes_per_sec, true), 'text-end');
      cell(tr, byte(n.rx_bytes), 'text-end'); cell(tr, byte(n.tx_bytes), 'text-end');
      cell(tr, `${fmt(n.rx_packets)} / ${fmt(n.tx_packets)}`, 'text-end');
      cell(tr, `${fmt(n.rx_errors + n.tx_errors)} / ${fmt(n.rx_drops + n.tx_drops)}`, 'text-end');
      return tr;
    }));
  }

  function raValue(key, value) {
    if (value == null) return '—';
    return key === 'frame_len' && frameSubslots[value] ? `${value} · ${frameSubslots[value]} subslots` : String(value);
  }
  function renderRa(s) {
    const available = s.radio.measured_at_ms > 0;
    const data = available ? s.radio.ra : { current: {}, limits: {}, load: 'Starting', window: null };
    const window = data.window;
    setText('ra-mode', available ? (data.dynamic ? 'Dynamic' : 'Static') : '—'); setText('ra-load', data.load || 'Starting');
    setTone('ra-load', data.load === 'Heavy' ? 'bad' : data.load === 'Contention' ? 'warn' : 'good');
    setText('ra-score', fmt(window?.sample_score)); setText('ra-ewma', fmt(window?.ewma_score, 1));
    const labels = { imm: 'IMM', wt: 'WT', nu: 'Nu', frame_len: 'Base frame length' };
    replace('ra-parameters', Object.entries(labels).map(([key, label]) => {
      const tr = document.createElement('tr'); cell(tr, label);
      cell(tr, raValue(key, data.current[key]), 'text-end');
      cell(tr, data.dynamic ? raValue(key, data.limits[key]?.[0]) : '—', 'text-end');
      cell(tr, data.dynamic ? raValue(key, data.limits[key]?.[1]) : '—', 'text-end');
      return tr;
    }));
    const extra = [
      ['Frame length factor', !available ? '—' : data.current.frame_len_factor ? 'On' : 'Off'],
      ['Timeslot pointer', fmt(data.current.ts_pointer)], ['Minimum PDU priority', fmt(data.current.min_pdu_prio)],
    ];
    replace('ra-extra', extra.map(([label, value]) => {
      const item = document.createElement('span'); const name = document.createTextNode(`${label} `);
      const val = document.createElement('b'); val.textContent = value; item.append(name, val); return item;
    }));
    const metrics = [
      ['First attempts', window?.first_attempts], ['Retries', window?.retry_attempts],
      ['Follow-up accesses', window?.followup_attempts], ['Invalid MAC accesses', window?.invalid_mac_access],
      ['CRC failures', window?.crc_failures], ['Pending registrations', window?.pending_registrations],
      ['Registration delivery failures', window?.registration_delivery_failures],
    ];
    replace('ra-measures', metrics.map(([label, value]) => {
      const item = document.createElement('div'); item.className = 'measure';
      const name = document.createElement('span'); name.textContent = label;
      const number = document.createElement('strong'); number.textContent = fmt(value);
      item.append(name, number); return item;
    }));
  }

  function pdpLabel(pdp) { return !pdp ? 'None' : !pdp.session ? 'Pending' : pdp.bearer ? 'Active' : 'Standby'; }
  function terminalDetailButton(t) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'btn btn-sm btn-outline-primary'; button.dataset.issi = t.issi;
    button.textContent = 'Details';
    button.addEventListener('click', () => { state.selectedTerminal = t.issi; renderTerminalModal(t); terminalModal.show(); });
    return button;
  }
  function renderOverviewTerminals(terminals, available) {
    const recent = [...terminals].sort((a, b) => (b.last_seen_ms || 0) - (a.last_seen_ms || 0) || a.issi - b.issi).slice(0, 6);
    const focused = document.activeElement?.closest('#overview-terminal-list button')?.dataset.issi;
    const rows = recent.map(t => {
      const row = document.createElement('div'); row.className = 'list-group-item overview-terminal-row';
      const identity = document.createElement('div'); identity.className = 'overview-terminal-identity';
      const issi = document.createElement('strong'); issi.textContent = t.issi;
      const registration = document.createElement('span'); registration.className = `badge text-bg-${t.registration === 'Active' ? 'success' : t.registration === 'Pending' ? 'warning' : 'secondary'}`;
      registration.textContent = t.registration;
      identity.append(issi, registration);
      const field = (label, value, className = '') => {
        const el = document.createElement('span'); el.className = `overview-terminal-field ${className}`;
        el.dataset.label = label; el.setAttribute('aria-label', `${label}: ${value}`); el.textContent = value;
        return el;
      };
      const groups = t.talkgroups || [];
      const groupLabel = groups.length ? `${groups.slice(0, 3).join(', ')}${groups.length > 3 ? ` +${groups.length - 3}` : ''}` : '—';
      row.append(identity,
        field('RSSI', t.rf ? `${fmt(t.rf.rssi_dbfs, 1)} dBFS` : '—'),
        field('Last seen', age(t.last_seen_ms)),
        field('Talkgroups', groupLabel, 'overview-terminal-groups'),
        field('PDP', pdpLabel(t.pdp)),
        terminalDetailButton(t));
      return row;
    });
    replace('overview-terminal-list', rows);
    if (focused) document.querySelector(`#overview-terminal-list button[data-issi="${focused}"]`)?.focus({ preventScroll: true });
    $('overview-terminal-empty').hidden = available && terminals.length > 0;
    $('overview-terminal-empty').textContent = available ? 'No registered terminals' : 'Awaiting radio';
    $('overview-all-terminals').textContent = terminals.length > 6 ? `View all ${terminals.length}` : 'View all';
  }
  function renderTerminalModal(t) {
    setText('terminal-modal-title', `Terminal ${t.issi}`);
    const fields = [
      ['Registration', t.registration], ['Talkgroups', t.talkgroups.join(', ') || 'None'],
      ['Last uplink', when(t.last_seen_ms)], ['RF measurement', t.rf ? when(t.rf.measured_at_ms) : 'Unavailable'],
      ['RSSI', t.rf ? `${fmt(t.rf.rssi_dbfs, 1)} dBFS` : 'Unavailable'],
      ['Frequency offset', t.rf ? `${fmt(t.rf.frequency_offset_hz, 1)} Hz` : 'Unavailable'],
      ['Training EVM', t.rf ? `${fmt(t.rf.evm_percent, 1)}%` : 'Unavailable'],
      ['Block errors', t.rf ? `${t.rf.block_errors} / ${t.rf.block_count}` : 'Unavailable'],
      ['PDP context', pdpLabel(t.pdp)], ['NSAPI', t.pdp ? String(t.pdp.nsapi) : '—'],
      ['IP address', t.pdp?.ipv4 || '—'], ['Packet timeslots', t.pdp?.timeslots?.length ? t.pdp.timeslots.map(n => `TS${n}`).join(', ') : '—'],
    ];
    replace('terminal-modal-details', fields.map(([label, value]) => {
      const item = document.createElement('div'), key = document.createElement('span'), val = document.createElement('strong');
      key.textContent = label; val.textContent = value; item.append(key, val); return item;
    }));
  }
  function renderTerminals(s) {
    const query = $('terminal-search').value.trim().toLowerCase(); const filter = $('terminal-filter').value; const sort = $('terminal-sort').value;
    const filtered = s.radio.terminals.filter(t => {
      if (filter === 'pdp' && !t.pdp) return false;
      if (filter === 'no-pdp' && t.pdp) return false;
      if (filter === 'active' && t.registration !== 'Active') return false;
      if (filter === 'pending' && t.registration !== 'Pending') return false;
      return !query || String(t.issi).includes(query) || t.talkgroups.some(g => String(g).includes(query));
    });
    filtered.sort((a, b) => sort === 'last-seen' ? (b.last_seen_ms || 0) - (a.last_seen_ms || 0) || a.issi - b.issi
      : sort === 'rssi' ? (b.rf?.rssi_dbfs ?? -Infinity) - (a.rf?.rssi_dbfs ?? -Infinity) || a.issi - b.issi
      : a.issi - b.issi);
    const pages = Math.max(1, Math.ceil(filtered.length / 25)); state.page = Math.min(state.page, pages - 1);
    setText('terminal-results', `${filtered.length} of ${s.radio.terminals.length}`);
    setText('terminal-page', `${state.page + 1} / ${pages}`);
    $('terminal-prev').disabled = state.page === 0; $('terminal-next').disabled = state.page >= pages - 1;
    $('terminal-empty').hidden = filtered.length !== 0;
    $('terminal-empty').textContent = s.radio.terminals.length ? 'No terminals match the filters' : 'No registered terminals';
    const focused = document.activeElement?.dataset?.issi;
    const rows = [];
    for (const t of filtered.slice(state.page * 25, (state.page + 1) * 25)) {
      const row = document.createElement('tr');
      cell(row, t.issi, 'issi'); cell(row, t.rf ? fmt(t.rf.rssi_dbfs, 1) : '—', 'text-end');
      cell(row, age(t.last_seen_ms)); cell(row, t.talkgroups.length ? t.talkgroups.join(', ') : '—', 'groups');
      cell(row, t.registration);
      cell(row, pdpLabel(t.pdp));
      const detailCell = document.createElement('td'); detailCell.appendChild(terminalDetailButton(t));
      row.appendChild(detailCell); rows.push(row);
    }
    replace('terminal-rows', rows);
    if (focused) document.querySelector(`#terminal-rows button[data-issi="${focused}"]`)?.focus({ preventScroll: true });
    if (state.selectedTerminal != null) {
      const selected = s.radio.terminals.find(t => t.issi === state.selectedTerminal);
      if (selected) renderTerminalModal(selected);
    }
  }
  for (const id of ['terminal-search', 'terminal-filter', 'terminal-sort']) $(id).addEventListener(id === 'terminal-search' ? 'input' : 'change', () => {
    state.page = 0; if (state.snapshot) renderTerminals(state.snapshot);
  });
  $('terminal-prev').addEventListener('click', () => { state.page--; if (state.snapshot) renderTerminals(state.snapshot); });
  $('terminal-next').addEventListener('click', () => { state.page++; if (state.snapshot) renderTerminals(state.snapshot); });
  $('overview-all-terminals').addEventListener('click', () => selectTab('terminals', true));
  $('network-select').addEventListener('change', drawCharts);

  function renderSwmi(s) {
    const swmi = s.swmi, radio = s.radio;
    setText('swmi-phase', swmi.phase || 'Connecting'); setTone('swmi-phase', radio.network_connected ? 'good' : swmi.connected ? 'warn' : 'bad');
    setText('swmi-rtt', swmi.rtt_ms == null || !swmi.connected ? 'Unavailable' : `${fmt(swmi.rtt_ms, 1)} ms`);
    setText('swmi-service', radio.network_connected ? 'Available' : 'Unavailable'); setTone('swmi-service', radio.network_connected ? 'good' : 'bad');
    setText('swmi-reconnects', fmt(swmi.reconnects));
    const address = s.swmi_host ? `${s.swmi_tls ? 'wss' : 'ws'}://${s.swmi_host}:${s.swmi_port}` : 'Not configured';
    replace('swmi-properties', [
      property('Server', address), property('Last connected', when(swmi.connected_at_ms)),
      property('Last received', when(swmi.last_receive_ms)), property('Last ping sample', when(swmi.rtt_measured_at_ms)),
      property('Provisioning accepted', radio.advertisement_accepted ? 'Yes' : 'No'),
      property('Recovery ready', radio.recovery_ready ? 'Yes' : 'No'),
      property('Radio TX allowed', radio.radio_tx_allowed ? 'Yes' : 'No'),
      property('Radio TX active', radio.radio_tx_active ? 'Yes' : 'No'),
      property('Local fallback', !radio.network_connected && radio.provisioned_once ? 'Active' : 'Inactive'),
      property('Last issue', swmi.last_error || 'None'),
    ]);
  }

  function render(s) {
    state.snapshot = s;
    const stale = !s.radio.measured_at_ms ? false : s.server_time_ms - s.radio.measured_at_ms > 5000;
    setConnectionStatus(stale ? 'Radio data stale' : s.radio.measured_at_ms ? null : 'Awaiting radio');
    renderOverview(s); renderCell(s); renderSystem(s); renderRa(s); renderTerminals(s); renderSwmi(s);
    drawCharts();
  }

  async function loadHistory() {
    const response = await fetch('/api/v1/history', { cache: 'no-store' });
    if (!response.ok) throw new Error(`History HTTP ${response.status}`);
    const data = await response.json();
    state.runId = data.run_id;
    state.history = data.points;
    drawCharts();
  }

  async function poll() {
    if (state.fetching || document.hidden) return;
    state.fetching = true;
    try {
      const response = await fetch('/api/v1/snapshot', { cache: 'no-store' });
      if (!response.ok) throw new Error(`Snapshot HTTP ${response.status}`);
      const data = await response.json(); state.lastResponse = Date.now();
      if (data.run_id !== state.runId || data.sample_seq > (state.history.at(-1)?.seq || 0) + 1) await loadHistory();
      if (data.latest_point && data.sample_seq > (state.history.at(-1)?.seq || 0)) {
        state.history.push(data.latest_point);
        if (state.history.length > 900) state.history.shift();
      }
      render(data);
    } catch (error) {
      setConnectionStatus('Connection unavailable');
    } finally { state.fetching = false; }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { loadHistory().catch(() => {}); poll(); } });
  setInterval(() => {
    if (state.lastResponse && Date.now() - state.lastResponse > 5000) setConnectionStatus('Connection unavailable');
    poll();
  }, 1000);
  loadHistory().catch(() => {}).finally(poll);
})();
