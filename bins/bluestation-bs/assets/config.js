(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = { revision: null, settings: null, loading: false, saving: false, frequencyBands: [], customDuplexEntry: 7 };
  const frequencyMath = globalThis.BlueStationFrequency;
  let nextHelpId = 0;
  const info = (text, label) => {
    const wrapper = document.createElement('span'); wrapper.className = 'config-help';
    const button = document.createElement('button'); button.type = 'button'; button.className = 'config-info'; button.textContent = 'i';
    button.setAttribute('aria-label', `About ${label}`); button.setAttribute('aria-expanded', 'false');
    const description = document.createElement('span'); description.className = 'config-help-text'; description.textContent = text;
    description.id = `config-help-${++nextHelpId}`; description.setAttribute('role', 'tooltip');
    button.setAttribute('aria-describedby', description.id);
    button.addEventListener('click', event => {
      event.stopPropagation();
      wrapper.classList.toggle('is-open');
      button.setAttribute('aria-expanded', String(wrapper.classList.contains('is-open')));
    });
    wrapper.append(button, description);
    return wrapper;
  };
  const labelFor = (id, label, help) => {
    const wrapper = document.createElement('div'); wrapper.className = 'config-label';
    const element = document.createElement('label'); element.htmlFor = id; element.textContent = label;
    wrapper.append(element);
    if (help) wrapper.append(info(help, label));
    return wrapper;
  };
  const get = (object, path) => path.split('.').reduce((value, key) => value?.[key], object);
  const fieldId = path => `config-${path.replaceAll('.', '-')}`;
  const numberSpecs = [
    ['random_access.update_interval_multiframes', 'Update interval', 1, 60, 'How often ACCESS-DEFINE can update the on-air parameters, in multiframes.'],
    ['random_access.startup_grace_multiframes', 'Startup grace', 0, 60, 'Multiframes before dynamic load control starts.'],
    ['random_access.recovery_step_multiframes', 'Recovery step', 1, 60, 'Low-load multiframes between steps back toward nominal access values.'],
    ['random_access.low_load_threshold', 'Low-load threshold', 0, 255, 'Scores at or below this threshold count as low load. Must be lower than the heavy-load threshold.'],
    ['random_access.high_load_threshold', 'Heavy-load threshold', 0, 255, 'Scores at or above this threshold count as heavy load.'],
    ['random_access.imm_min', 'IMM minimum', 0, 15, 'Immediate-access code: 0 always randomizes; 1–14 randomize after that many TDMA frames; 15 permits immediate access.'],
    ['random_access.imm_max', 'IMM maximum', 0, 15, 'Upper bound for the dynamic immediate-access code.'],
    ['random_access.wt_min', 'WT minimum', 1, 15, 'Minimum response waiting time in downlink opportunities; code 0 is reserved.'],
    ['random_access.wt_max', 'WT maximum', 1, 15, 'Maximum response waiting time in downlink opportunities.'],
    ['random_access.nu_min', 'Nu minimum', 1, 15, 'Minimum number of permitted access attempts.'],
    ['random_access.nu_max', 'Nu maximum', 1, 15, 'Maximum number of permitted access attempts.'],
    ['random_access.frame_len_min', 'Frame length minimum', 1, 15, 'Lower bound of the on-air base frame-length code; this determines random-access subslots.'],
    ['random_access.frame_len_max', 'Frame length maximum', 1, 15, 'Upper bound of the on-air base frame-length code.'],
    ['random_access.retry_window_multiframes', 'Retry window', 1, 60, 'Accesses by the same ISSI within this many multiframes count as retries.'],
    ['random_access.retry_weight_percent', 'Retry weight', 1, 100, 'Weight applied to retry attempts in the load score, as a percentage.'],
    ['random_access.ewma_alpha_percent', 'EWMA alpha', 1, 100, 'Weight of the newest measurement in the smoothed load score.'],
    ['random_access.frame_factor_activation_windows', 'Frame factor activation', 1, 60, 'Consecutive loaded measurement windows before the frame-length factor is enabled.'],
    ['random_access.frame_factor_release_windows', 'Frame factor release', 1, 60, 'Consecutive recovered windows before the frame-length factor is disabled.'],
    ['cell_reselect.slow_reselect_threshold_above_fast_db', 'Slow threshold above fast', 0, 30, 'Difference added to the fast threshold for a radio-improvable link, in dB.'],
    ['cell_reselect.fast_reselect_threshold_db', 'Fast reselect threshold', 0, 30, 'Serving-cell threshold for a radio-relinquishable link above C1 = 0, in dB.'],
    ['cell_reselect.slow_reselect_hysteresis_db', 'Slow reselect hysteresis', 0, 30, 'Neighbour advantage required before slow reselection, in dB.'],
    ['cell_reselect.fast_reselect_hysteresis_db', 'Fast reselect hysteresis', 0, 30, 'Neighbour advantage required before fast reselection, in dB.'],
  ];
  const dbSpecs = [
    ['cell_info.rxlev_access_min_dbm', 'Minimum RX access level', -125, -50, 5, 'Minimum received level for cell access and reselection. The air-interface code uses 5 dB steps from −125 dBm.'],
    ['cell_info.access_parameter_dbm', 'Access parameter', -53, -23, 2, 'Used by the MS for uplink power control. The air-interface code uses 2 dB steps from −53 dBm.'],
  ];
  const stepFor = path => path.startsWith('cell_reselect.') ? 2 : 1;

  function numericField(spec, settings) {
    const [path, label, min, max, help] = spec;
    const step = spec[5] || stepFor(path);
    const id = fieldId(path), wrapper = document.createElement('div');
    wrapper.className = 'config-field';
    wrapper.append(labelFor(id, label, help));
    const input = document.createElement('input'); input.id = id; input.name = path;
    input.type = 'number'; input.className = 'form-control'; input.required = true;
    input.min = min; input.max = max; input.step = step; input.value = get(settings, path);
    wrapper.append(input);
    if (path.endsWith('_percent')) {
      const unit = document.createElement('span'); unit.className = 'config-unit'; unit.textContent = '%'; wrapper.append(unit);
    }
    return wrapper;
  }

  function toggle(path, label, help, settings) {
    const id = fieldId(path), wrapper = document.createElement('div');
    wrapper.className = 'form-check form-switch config-switch';
    const input = document.createElement('input'); input.type = 'checkbox'; input.className = 'form-check-input';
    input.id = id; input.name = path; input.checked = !!get(settings, path);
    wrapper.append(input, labelFor(id, label, help));
    return wrapper;
  }

  function group(panel, title, specs, settings) {
    const section = document.createElement('section'); section.className = 'config-group';
    const heading = document.createElement('h2'); heading.textContent = title; section.append(heading);
    const grid = document.createElement('div'); grid.className = 'config-grid';
    specs.forEach(spec => grid.append(numericField(spec, settings)));
    section.append(grid); panel.append(section);
  }

  function selectField(path, label, help, options, settings) {
    const id = fieldId(path), wrapper = document.createElement('div'); wrapper.className = 'config-field';
    wrapper.append(labelFor(id, label, help));
    const select = document.createElement('select'); select.id = id; select.name = path; select.className = 'form-select';
    for (const [value, text] of options) {
      const option = document.createElement('option'); option.value = value; option.textContent = text; select.append(option);
    }
    select.value = get(settings, path) ?? '';
    wrapper.append(select); return wrapper;
  }

  function frequencyInput(name, label, help, value, unit, readOnly = false) {
    const id = fieldId(`frequency.${name}`), wrapper = document.createElement('div'); wrapper.className = 'config-field';
    wrapper.append(labelFor(id, label, help));
    const input = document.createElement('input'); input.id = id; input.type = readOnly ? 'text' : 'number';
    input.className = 'form-control'; input.readOnly = readOnly; input.value = value ?? '';
    if (!readOnly) { input.required = true; input.step = '0.000001'; input.min = '0'; input.max = '4294.967295'; }
    const group = document.createElement('div'); group.className = 'input-group';
    const suffix = document.createElement('span'); suffix.className = 'input-group-text'; suffix.textContent = unit;
    group.append(input, suffix); wrapper.append(group); return wrapper;
  }

  function readFrequency() {
    const custom = $('config-frequency-duplex_spacing').value === 'custom';
    return {
      frequency_band: Number($('config-frequency-frequency_band').value),
      main_carrier: $('config-frequency-main_carrier').valueAsNumber,
      offset_hz: Number($('config-frequency-offset_hz').value),
      duplex_spacing: custom ? state.customDuplexEntry : Number($('config-frequency-duplex_spacing').value),
      custom_split_mhz: custom ? $('config-frequency-custom_split_mhz').valueAsNumber : null,
      reverse_operation: $('config-frequency-reverse_operation').value === 'true',
    };
  }

  function refreshDuplexOptions(selected) {
    const select = $('config-frequency-duplex_spacing');
    const band = state.frequencyBands.find(item => item.value === Number($('config-frequency-frequency_band').value));
    select.replaceChildren();
    for (const entry of band?.duplex_spacings || []) {
      const option = document.createElement('option'); option.value = entry.value;
      option.textContent = entry.spacing_mhz === 0 ? '0 MHz — no split' : `${entry.spacing_mhz} MHz`;
      select.append(option);
    }
    const custom = document.createElement('option'); custom.value = 'custom'; custom.textContent = 'Custom split'; select.append(custom);
    select.value = String(selected);
    if (!select.value) select.value = String(band?.duplex_spacings.find(entry => entry.spacing_mhz > 0)?.value ?? 2);
  }

  function updateFrequencyPreview(preserveDownlink = false) {
    const frequency = readFrequency(), customInput = $('config-frequency-custom_split_mhz');
    const custom = frequency.custom_split_mhz !== null;
    customInput.closest('.config-field').hidden = !custom; customInput.disabled = !custom;
    customInput.required = custom; customInput.setCustomValidity('');
    const valid = frequencyMath.validComponents(frequency);
    const uplink = valid ? frequencyMath.uplinkHz(frequency, state.frequencyBands) : null;
    if (!preserveDownlink && valid) $('config-frequency-downlink_mhz').value = (frequencyMath.componentsToHz(frequency) / 1000000).toFixed(6);
    $('config-frequency-uplink_mhz').value = uplink == null ? '—' : (uplink / 1000000).toFixed(6);
    const invalidSplit = custom && (!Number.isFinite(frequency.custom_split_mhz) || uplink == null);
    if (invalidSplit) customInput.setCustomValidity('Enter a split that produces a valid uplink frequency.');
    updateRestartPreview();
  }

  function updateRestartPreview() {
    const frequencyChanged = state.settings.frequency && !frequencyMath.sameSettings(readFrequency(), state.settings.frequency);
    const colourChanged = $('config-cell_info-colour_code').valueAsNumber !== state.settings.cell_info.colour_code;
    if ($('config-frequency-restart-note')) $('config-frequency-restart-note').hidden = !frequencyChanged;
    $('config-colour-code-restart-note').hidden = !colourChanged;
    $('config-save').textContent = frequencyChanged || colourChanged ? 'Save & restart' : 'Save & apply';
  }

  function renderFrequency(cell, settings) {
    if (!settings.frequency) return;
    const frequency = settings.frequency;
    state.customDuplexEntry = frequency.custom_split_mhz != null ? frequency.duplex_spacing : 7;
    const section = document.createElement('section'); section.className = 'config-group';
    const heading = document.createElement('h2'); heading.textContent = 'Radio frequencies'; section.append(heading);
    const pair = document.createElement('div'); pair.className = 'config-grid config-frequency-pair';
    pair.append(frequencyInput('downlink_mhz', 'Downlink frequency', 'BS transmit frequency. Enter MHz on the TETRA 6.25 kHz raster; band, carrier and offset update automatically.', (frequencyMath.componentsToHz(frequency) / 1000000).toFixed(6), 'MHz'));
    pair.append(frequencyInput('uplink_mhz', 'Uplink frequency', 'BS receive frequency, calculated from the downlink, duplex spacing and uplink direction.', '', 'MHz', true));
    const downlink = pair.querySelector('input'); downlink.step = '0.00625'; downlink.min = '99.99375'; downlink.max = '999.9875';
    const invalid = document.createElement('div'); invalid.id = 'config-frequency-error'; invalid.className = 'invalid-feedback d-block'; invalid.hidden = true; pair.firstChild.append(invalid);
    section.append(pair);
    const components = document.createElement('div'); components.className = 'config-grid mt-3';
    components.append(selectField('frequency.frequency_band', 'Frequency band', 'The base/reference frequency in the TETRA carrier formula; not the lower edge of an allocated radio band.', state.frequencyBands.map(band => [String(band.value), `${band.base_mhz} MHz base`]), settings));
    components.append(numericField(['frequency.main_carrier', 'Main carrier', 0, 3999, 'Carrier number in 25 kHz steps above the band base. This is the air-interface carrier number, not the radio channel name.'], settings));
    components.append(selectField('frequency.offset_hz', 'Carrier offset', 'Adjustment to the 25 kHz carrier raster.', [['-6250', '−6.25 kHz'], ['0', '0 kHz'], ['6250', '+6.25 kHz'], ['12500', '+12.5 kHz']], settings));
    section.append(components);
    const duplex = document.createElement('div'); duplex.className = 'config-grid mt-3';
    duplex.append(selectField('frequency.duplex_spacing', 'Duplex spacing', 'ETSI table values depend on the frequency band. Custom split uses an externally defined duplex entry; terminals must know that split before transmitting.', [], settings));
    duplex.append(selectField('frequency.reverse_operation', 'Uplink direction', 'Normal operation subtracts the split from the downlink. Reverse operation adds it.', [['false', 'Below downlink (normal)'], ['true', 'Above downlink (reverse)']], settings));
    const standard = frequencyMath.splitHz(frequency, state.frequencyBands);
    duplex.append(frequencyInput('custom_split_mhz', 'Custom split', 'The split in MHz is stored in Hz. Custom entry 7 is not sent as a numeric spacing over the air; configure the same split in the terminals.', frequency.custom_split_mhz ?? (standard == null ? '' : standard / 1000000), 'MHz'));
    section.append(duplex);
    const note = document.createElement('div'); note.id = 'config-frequency-restart-note'; note.className = 'alert alert-warning mt-3 mb-0'; note.textContent = 'Frequency or duplex changes restart the BS when saved.'; note.hidden = true; section.append(note);
    cell.append(section);
    refreshDuplexOptions(frequency.custom_split_mhz != null ? 'custom' : frequency.duplex_spacing);
    downlink.addEventListener('input', () => {
      downlink.setCustomValidity('');
      const next = downlink.value === '' ? null : frequencyMath.mhzToComponents(downlink.valueAsNumber, readFrequency());
      invalid.hidden = !!next;
      if (!next) {
        invalid.textContent = 'Use a supported TETRA frequency in 6.25 kHz steps.';
        downlink.setCustomValidity(invalid.textContent); $('config-frequency-uplink_mhz').value = '—'; return;
      }
      const previousBand = $('config-frequency-frequency_band').value;
      for (const key of ['frequency_band', 'main_carrier', 'offset_hz']) $(fieldId(`frequency.${key}`)).value = next[key];
      if (previousBand !== String(next.frequency_band)) refreshDuplexOptions($('config-frequency-duplex_spacing').value);
      updateFrequencyPreview(true);
    });
    downlink.addEventListener('change', () => { if (downlink.checkValidity()) updateFrequencyPreview(); });
    for (const input of components.querySelectorAll('input, select')) input.addEventListener('input', () => {
      downlink.setCustomValidity(''); invalid.hidden = true;
      if (input.id === 'config-frequency-frequency_band') refreshDuplexOptions($('config-frequency-duplex_spacing').value);
      updateFrequencyPreview();
    });
    for (const input of duplex.querySelectorAll('input, select')) input.addEventListener('input', () => {
      if (input.id === 'config-frequency-duplex_spacing' && input.value === 'custom' && frequency.custom_split_mhz == null) state.customDuplexEntry = 7;
      updateFrequencyPreview(true);
    });
    updateFrequencyPreview();
  }

  function render(settings) {
    const ra = $('config-ra'); ra.replaceChildren();
    ra.append(toggle('random_access.enabled', 'Dynamic random access', 'Adapt IMM, WT, Nu and frame length to measured access load.', settings));
    group(ra, 'Timing & load', numberSpecs.slice(0, 5), settings);
    group(ra, 'On-air limits', numberSpecs.slice(5, 13), settings);
    group(ra, 'Measurement', numberSpecs.slice(13, 18), settings);

    const broadcast = $('config-broadcast'); broadcast.replaceChildren();
    const neighbours = document.createElement('section'); neighbours.className = 'config-group';
    const title = document.createElement('h2'); title.textContent = 'Neighbour cells'; neighbours.append(title);
    const wrapper = document.createElement('div'); wrapper.className = 'config-field';
    wrapper.append(labelFor('config-neighbours', 'SwMI base-station IDs', 'One stable base-station ID per line. Order determines the advertised CA neighbour identifiers; maximum 31.'));
    const textarea = document.createElement('textarea'); textarea.id = 'config-neighbours'; textarea.className = 'form-control';
    textarea.rows = 4; textarea.value = settings.neighbour_cells.join('\n'); wrapper.append(textarea);
    neighbours.append(wrapper); broadcast.append(neighbours);
    group(broadcast, 'Cell reselection', numberSpecs.slice(18), settings);
    const time = document.createElement('section'); time.className = 'config-group';
    const timeTitle = document.createElement('h2'); timeTitle.textContent = 'Network time'; time.append(timeTitle);
    time.append(toggle('time_enabled', 'Broadcast network time', 'Required when neighbour cells are configured.', settings));
    const timeField = document.createElement('div'); timeField.className = 'config-field config-timezone';
    timeField.append(labelFor('config-timezone', 'Timezone', 'IANA timezone name used in D-NWRK-BROADCAST, for example Europe/Amsterdam.'));
    const timezone = document.createElement('input'); timezone.id = 'config-timezone'; timezone.className = 'form-control';
    timezone.type = 'text'; timezone.autocomplete = 'off'; timezone.placeholder = 'Europe/Amsterdam'; timezone.value = settings.timezone || '';
    timeField.append(timezone); time.append(timeField); broadcast.append(time);

    const cell = $('config-cell'); cell.replaceChildren();
    const radio = document.createElement('section'); radio.className = 'config-group';
    const radioTitle = document.createElement('h2'); radioTitle.textContent = 'Transmitter'; radio.append(radioTitle);
    radio.append(toggle('tx_enabled', 'Enable TX', 'Switch the transmitter on or off live when saved. Reception and the SwMI connection remain active. TX also requires permission from the network.', settings));
    cell.append(radio);
    group(cell, 'Cell identity', [['cell_info.colour_code', 'Colour code (CC)', 0, 63, 'Identifies the cell and determines radio scrambling. 0 uses the predefined scrambling sequence; 1–63 select an operator-defined colour code. Changing this restarts the BS when saved.']], settings);
    const colourNote = document.createElement('div'); colourNote.id = 'config-colour-code-restart-note';
    colourNote.className = 'alert alert-warning mt-3 mb-0'; colourNote.textContent = 'Colour code changes restart the BS when saved.';
    colourNote.hidden = true; cell.lastChild.append(colourNote);
    $('config-cell_info-colour_code').addEventListener('input', updateRestartPreview);
    renderFrequency(cell, settings);
    const cellGroup = document.createElement('section'); cellGroup.className = 'config-group';
    const cellTitle = document.createElement('h2'); cellTitle.textContent = 'Cell access & power'; cellGroup.append(cellTitle);
    const cellGrid = document.createElement('div'); cellGrid.className = 'config-grid';
    const powerOptions = [['', 'Reserved (code 0)']];
    for (let dbm = 15; dbm <= 45; dbm += 5) powerOptions.push([String(dbm), `${dbm} dBm`]);
    cellGrid.append(selectField('cell_info.ms_txpwr_max_cell_dbm', 'Maximum MS transmit power', 'Upper limit on terminal transmit power in this cell; code 0 is reserved by ETSI.', powerOptions, settings));
    for (const [path, label, min, max, step, help] of dbSpecs) {
      const options = [];
      for (let dbm = min; dbm <= max; dbm += step) options.push([String(dbm), `${dbm} dBm`]);
      cellGrid.append(selectField(path, label, help, options, settings));
    }
    cellGroup.append(cellGrid); cell.append(cellGroup);

    const lst = document.createElement('section'); lst.className = 'config-group';
    const lstTitle = document.createElement('h2'); lstTitle.textContent = 'Local site trunking'; lst.append(lstTitle);
    lst.append(toggle('allow_lst', 'Allow local site trunking', 'After a SwMI connection is lost, keep transmitting with the last accepted cell configuration.', settings));
    cell.append(lst);
    updateRestartPreview();
  }

  function readForm() {
    const settings = structuredClone(state.settings);
    if (settings.frequency) settings.frequency = readFrequency();
    for (const [path] of numberSpecs) {
      const keys = path.split('.'); settings[keys[0]][keys[1]] = Number($(fieldId(path)).value);
    }
    settings.random_access.enabled = $('config-random_access-enabled').checked;
    settings.neighbour_cells = $('config-neighbours').value.split(/\r?\n/).map(id => id.trim()).filter(Boolean);
    settings.time_enabled = $('config-time_enabled').checked;
    settings.timezone = $('config-timezone').value.trim() || null;
    settings.cell_info.colour_code = $('config-cell_info-colour_code').valueAsNumber;
    settings.cell_info.ms_txpwr_max_cell_dbm = $('config-cell_info-ms_txpwr_max_cell_dbm').value === '' ? null : Number($('config-cell_info-ms_txpwr_max_cell_dbm').value);
    for (const [path] of dbSpecs) settings.cell_info[path.split('.')[1]] = Number($(fieldId(path)).value);
    settings.allow_lst = $('config-allow_lst').checked;
    settings.tx_enabled = $('config-tx_enabled').checked;
    return settings;
  }

  function message(text, tone) {
    const node = $('config-message'); node.textContent = text;
    node.className = `alert alert-${tone}`; node.hidden = !text;
  }

  async function load() {
    if (state.loading) return;
    state.loading = true; $('config-save').disabled = true;
    message('Loading configuration…', 'info');
    try {
      const response = await fetch('/api/v1/config', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      state.revision = data.revision; state.settings = data.settings; state.frequencyBands = data.frequency_bands || [];
      render(data.settings); $('config-save').disabled = false;
      message('', 'info');
      return true;
    } catch (error) {
      message(`Could not load configuration: ${error.message}`, 'danger');
      return false;
    } finally { state.loading = false; }
  }

  async function waitForRestart(oldRunId) {
    for (let attempt = 0; attempt < 60; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 1500));
      try {
        const response = await fetch('/api/v1/snapshot', { cache: 'no-store' });
        if (!response.ok) continue;
        const snapshot = await response.json();
        if (snapshot.run_id !== oldRunId) {
          if (await load()) message('Configuration saved. Radio settings applied after restart.', 'success');
          return;
        }
      } catch (_) { /* The radio is restarting. */ }
    }
    message('Configuration saved, but the radio restart could not be confirmed. Check the service status.', 'warning');
  }

  $('config-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (state.saving || !state.revision || !$('config-form').reportValidity()) return;
    state.saving = true; $('config-save').disabled = true; message('Saving configuration…', 'info');
    try {
      const response = await fetch('/api/v1/config', {
        method: 'PUT', cache: 'no-store', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision: state.revision, settings: readForm() }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (data.restarting) {
        message('Configuration saved. Radio restarting…', 'info');
        await waitForRestart(data.run_id); return;
      }
      if (!data.applied) throw new Error('The base station did not confirm the live update');
      if (await load()) message(data.changed ? 'Configuration saved and applied live.' : 'Configuration already up to date.', 'success');
      else message('Configuration was applied, but could not be reloaded. Refresh this page before editing again.', 'warning');
    } catch (error) {
      message(`Could not save configuration: ${error.message}`, 'danger');
    } finally { state.saving = false; $('config-save').disabled = false; }
  });
  $('config-reload').addEventListener('click', load);
  const closeHelp = () => {
    for (const help of document.querySelectorAll('.config-help.is-open')) {
      help.classList.remove('is-open'); help.querySelector('button').setAttribute('aria-expanded', 'false');
    }
  };
  document.addEventListener('click', event => { if (!event.target.closest('.config-help')) closeHelp(); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') closeHelp(); });
  for (const button of document.querySelectorAll('[data-config-section]')) {
    button.addEventListener('click', () => {
      for (const tab of document.querySelectorAll('[data-config-section]')) {
        const active = tab === button; tab.classList.toggle('active', active); tab.setAttribute('aria-pressed', String(active));
        $(`config-${tab.dataset.configSection}`).hidden = !active;
      }
    });
  }
  const ensureLoaded = () => { if (!state.settings && !state.loading) load(); };
  $('tab-config').addEventListener('click', ensureLoaded);
  $('tab-config').addEventListener('focus', ensureLoaded);
})();
