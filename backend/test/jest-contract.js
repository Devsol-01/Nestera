module.exports = {
    moduleFileExtensions: ['js', 'json', 'ts'],
    rootDir: '..',
    testEnvironment: 'node',
    testRegex: '.contract.spec.ts$',
    transform: {
        '^.+\\.(t|j)s$': [
            'ts-jest',
            {
                tsconfig: {
                    skipLibCheck: true,
                    forceConsistentCasingInFileNames: true,
                    moduleResolution: 'bundler',
                    types: ['jest', 'node'],
                },
            },
        ],
    },
};
