const { test } = require('node:test');
const assert = require('node:assert/strict');
require('../assets/frequency.js');
const f = globalThis.BlueStationFrequency;
const bands = [
  { value: 3, duplex_spacings: [{ value: 0, spacing_mhz: 10 }] },
  { value: 4, duplex_spacings: [{ value: 0, spacing_mhz: 10 }, { value: 4, spacing_mhz: 5 }] },
  { value: 9, duplex_spacings: [{ value: 1, spacing_mhz: 45 }] },
];

test('MHz entry matches the ETSI 390.0125 MHz example and quarter-raster offsets', () => {
  for (const [mhz, expected] of [
    [390.0125, { frequency_band: 3, main_carrier: 3600, offset_hz: 12500 }],
    [421.60625, { frequency_band: 4, main_carrier: 864, offset_hz: 6250 }],
    [421.59375, { frequency_band: 4, main_carrier: 864, offset_hz: -6250 }],
    [915, { frequency_band: 9, main_carrier: 600, offset_hz: 0 }],
    [499.99375, { frequency_band: 5, main_carrier: 0, offset_hz: -6250 }],
  ]) assert.deepEqual(f.mhzToComponents(mhz), expected);
});

test('MHz and components round-trip at both band boundaries for all offsets', () => {
  for (let band = 1; band <= 9; band++) for (const carrier of [0, 1, 3999]) for (const offset of f.offsets) {
    const original = { frequency_band: band, main_carrier: carrier, offset_hz: offset };
    const hz = f.componentsToHz(original);
    assert.deepEqual(f.mhzToComponents(hz / 1000000, original), original);
    assert.equal(f.componentsToHz(f.mhzToComponents(hz / 1000000)), hz);
  }
});

test('unsupported or off-raster frequencies are not silently rounded', () => {
  for (const mhz of [0, 99, 1000, 421.601, 421.6062501, NaN, Infinity]) assert.equal(f.mhzToComponents(mhz), null);
});

test('uplink uses the band-specific spacing and normal/reverse direction', () => {
  const radio = { frequency_band: 9, main_carrier: 600, offset_hz: 0, duplex_spacing: 1, custom_split_mhz: null, reverse_operation: false };
  assert.equal(f.uplinkHz(radio, bands), 870000000);
  assert.equal(f.uplinkHz({ ...radio, reverse_operation: true }, bands), 960000000);
  assert.equal(f.uplinkHz({ ...radio, duplex_spacing: 7, custom_split_mhz: 7.6 }, bands), 907400000);
  assert.equal(f.uplinkHz({ ...radio, duplex_spacing: 7, custom_split_mhz: 1000 }, bands), null);
  assert.equal(f.uplinkHz({ ...radio, duplex_spacing: 6 }, bands), null);
});

test('the pending restart detects changes to the advertised representation too', () => {
  const original = { frequency_band: 4, main_carrier: 864, offset_hz: 6250, duplex_spacing: 0, custom_split_mhz: null, reverse_operation: false };
  assert.equal(f.sameSettings(original, { ...original }), true);
  assert.equal(f.sameSettings(original, { ...original, duplex_spacing: 7, custom_split_mhz: 10 }), false);
});
