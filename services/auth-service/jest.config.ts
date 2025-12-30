import type { Config } from 'jest';

const config: Config = {
  // Use the ESM preset for ts-jest to handle "type": "module"
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    // Transform .ts files using ts-jest with ESM support enabled
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  // If you use .js extensions in your imports (required for NodeNext), 
  // this maps them back to the .ts files for Jest
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
};

export default config;