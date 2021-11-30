const webpack = require('webpack');

module.exports = {
    mode: 'development',
    resolve: {
        alias: {
            '@protobufjs/inquire': require.resolve('./src/errata/inquire'),
        },
        fallback: {
            stream: require.resolve('stream-browserify'),
        },
    },
    plugins: [
        new webpack.ProvidePlugin({
            process: 'process/browser',
            Buffer: ['buffer', 'Buffer'],
        }),
    ],
};
