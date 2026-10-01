(() => {
  'use strict';
  const offsets = [-6250, 0, 6250, 12500];
  const componentsToHz = frequency => frequency.frequency_band * 100000000 + frequency.main_carrier * 25000 + frequency.offset_hz;
  const validComponents = f => Number.isInteger(f.frequency_band) && f.frequency_band >= 1 && f.frequency_band <= 9
    && Number.isInteger(f.main_carrier) && f.main_carrier >= 0 && f.main_carrier < 4000 && offsets.includes(f.offset_hz);
  function mhzToComponents(mhz, preferred) {
    const rawHz = Number(mhz) * 1000000, hz = Math.round(rawHz);
    if (!Number.isFinite(rawHz) || Math.abs(rawHz - hz) > 0.00001 || hz % 6250 !== 0) return null;
    if (preferred && validComponents(preferred) && componentsToHz(preferred) === hz) return { ...preferred };
    for (let band = 1; band <= 9; band++) {
      const carrier = Math.floor((hz - band * 100000000 + 6250) / 25000);
      const f = { frequency_band: band, main_carrier: carrier, offset_hz: hz - band * 100000000 - carrier * 25000 };
      if (validComponents(f)) return f;
    }
    return null;
  }
  function splitHz(frequency, bands) {
    if (frequency.custom_split_mhz != null) return Math.round(frequency.custom_split_mhz * 1000000);
    const entry = bands.find(band => band.value === frequency.frequency_band)?.duplex_spacings.find(entry => entry.value === frequency.duplex_spacing);
    return entry ? Math.round(entry.spacing_mhz * 1000000) : null;
  }
  function uplinkHz(frequency, bands) {
    const split = splitHz(frequency, bands);
    if (split == null || !Number.isFinite(split) || split < 0) return null;
    const hz = componentsToHz(frequency) + (frequency.reverse_operation ? split : -split);
    return hz > 0 && hz <= 4294967295 ? hz : null;
  }
  const sameSettings = (a, b) => ['frequency_band', 'main_carrier', 'offset_hz', 'duplex_spacing', 'custom_split_mhz', 'reverse_operation']
    .every(key => (a?.[key] ?? null) === (b?.[key] ?? null));
  globalThis.BlueStationFrequency = { offsets, componentsToHz, validComponents, mhzToComponents, splitHz, uplinkHz, sameSettings };
})();
