const { createTransformer } = require('babel-jest');

const babelOptions = {
  presets: [
    [
      '@babel/preset-env',
      {
        targets: {
          node: 'current',
        },
      },
    ],
    '@babel/preset-typescript',
  ],
};

module.exports = createTransformer(babelOptions);
