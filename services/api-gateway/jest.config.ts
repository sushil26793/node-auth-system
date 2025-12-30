
import type { Config } from 'jest';

const config: Config = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    // extensionsToTreatAsEsm: ['.ts'], // Removed for CJS
    transform: {
        '^.+\\.tsx?$': [
            'ts-jest',
            {
                // useESM: true, // Removed for CJS
            },
        ],
    },
    testMatch: ['**/tests/**/*.test.ts'],
    moduleFileExtensions: ['ts', 'js', 'json', 'node'],
    clearMocks: true,
};

export default config;
