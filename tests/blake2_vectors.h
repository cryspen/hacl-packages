#pragma once

typedef struct
{
  uint8_t* input;
  size_t input_len;
  uint8_t* key;
  size_t key_len;
  uint8_t* expected;
  size_t expected_len;
} blake2_test_vector;

static uint8_t input2b1[44] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
  0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU
};

static uint8_t key2b1[64] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
  0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU,
  0x2cU, 0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3aU, 0x3bU, 0x3cU, 0x3dU, 0x3eU, 0x3fU
};

static uint8_t expected2b1[64] = {
  0xc8U, 0xf6U, 0x8eU, 0x69U, 0x6eU, 0xd2U, 0x82U, 0x42U, 0xbfU, 0x99U, 0x7fU,
  0x5bU, 0x3bU, 0x34U, 0x95U, 0x95U, 0x08U, 0xe4U, 0x2dU, 0x61U, 0x38U, 0x10U,
  0xf1U, 0xe2U, 0xa4U, 0x35U, 0xc9U, 0x6eU, 0xd2U, 0xffU, 0x56U, 0x0cU, 0x70U,
  0x22U, 0xf3U, 0x61U, 0xa9U, 0x23U, 0x4bU, 0x98U, 0x37U, 0xfeU, 0xeeU, 0x90U,
  0xbfU, 0x47U, 0x92U, 0x2eU, 0xe0U, 0xfdU, 0x5fU, 0x8dU, 0xdfU, 0x82U, 0x37U,
  0x18U, 0xd8U, 0x6dU, 0x1eU, 0x16U, 0xc6U, 0x09U, 0x00U, 0x71U
};

static uint8_t input2b13[128] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU,
  0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU,
  0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU, 0x40U, 0x41U,
  0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4AU, 0x4BU, 0x4CU,
  0x4DU, 0x4EU, 0x4FU, 0x50U, 0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U,
  0x58U, 0x59U, 0x5AU, 0x5BU, 0x5CU, 0x5DU, 0x5EU, 0x5FU, 0x60U, 0x61U, 0x62U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU,
  0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U,
  0x79U, 0x7AU, 0x7BU, 0x7CU, 0x7DU, 0x7EU, 0x7FU
};

static uint8_t key2b13[64] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU,
  0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU,
  0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU
};

static uint8_t expected2b13[64] = {
  0x72U, 0x06U, 0x5EU, 0xE4U, 0xDDU, 0x91U, 0xC2U, 0xD8U, 0x50U, 0x9FU, 0xA1U,
  0xFCU, 0x28U, 0xA3U, 0x7CU, 0x7FU, 0xC9U, 0xFAU, 0x7DU, 0x5BU, 0x3FU, 0x8AU,
  0xD3U, 0xD0U, 0xD7U, 0xA2U, 0x56U, 0x26U, 0xB5U, 0x7BU, 0x1BU, 0x44U, 0x78U,
  0x8DU, 0x4CU, 0xAFU, 0x80U, 0x62U, 0x90U, 0x42U, 0x5FU, 0x98U, 0x90U, 0xA3U,
  0xA2U, 0xA3U, 0x5AU, 0x90U, 0x5AU, 0xB4U, 0xB3U, 0x7AU, 0xCFU, 0xD0U, 0xDAU,
  0x6EU, 0x45U, 0x17U, 0xB2U, 0x52U, 0x5CU, 0x96U, 0x51U, 0xE4U
};

static uint8_t input2s1[3] = { 0x61U, 0x62U, 0x63U };

static uint8_t key2s1[0] = {};

static uint8_t expected2s1[32] = {
  0x50U, 0x8CU, 0x5EU, 0x8CU, 0x32U, 0x7CU, 0x14U, 0xE2U, 0xE1U, 0xA7U, 0x2BU,
  0xA3U, 0x4EU, 0xEBU, 0x45U, 0x2FU, 0x37U, 0x45U, 0x8BU, 0x20U, 0x9EU, 0xD6U,
  0x3AU, 0x29U, 0x4DU, 0x99U, 0x9BU, 0x4CU, 0x86U, 0x67U, 0x59U, 0x82U
};

static uint8_t input2s2[1] = { 0x00U };

static uint8_t key2s2[32] = { 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U,
                              0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
                              0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U,
                              0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU,
                              0x1cU, 0x1dU, 0x1eU, 0x1fU };

static uint8_t expected2s2[32] = {
  0x40U, 0xd1U, 0x5fU, 0xeeU, 0x7cU, 0x32U, 0x88U, 0x30U, 0x16U, 0x6aU, 0xc3U,
  0xf9U, 0x18U, 0x65U, 0x0fU, 0x80U, 0x7eU, 0x7eU, 0x01U, 0xe1U, 0x77U, 0x25U,
  0x8cU, 0xdcU, 0x0aU, 0x39U, 0xb1U, 0x1fU, 0x59U, 0x80U, 0x66U, 0xf1U
};

static uint8_t input2s3[255] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
  0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU,
  0x2cU, 0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3aU, 0x3bU, 0x3cU, 0x3dU, 0x3eU, 0x3fU, 0x40U, 0x41U,
  0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4aU, 0x4bU, 0x4cU,
  0x4dU, 0x4eU, 0x4fU, 0x50U, 0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U,
  0x58U, 0x59U, 0x5aU, 0x5bU, 0x5cU, 0x5dU, 0x5eU, 0x5fU, 0x60U, 0x61U, 0x62U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6aU, 0x6bU, 0x6cU, 0x6dU,
  0x6eU, 0x6fU, 0x70U, 0x71U, 0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U,
  0x79U, 0x7aU, 0x7bU, 0x7cU, 0x7dU, 0x7eU, 0x7fU, 0x80U, 0x81U, 0x82U, 0x83U,
  0x84U, 0x85U, 0x86U, 0x87U, 0x88U, 0x89U, 0x8aU, 0x8bU, 0x8cU, 0x8dU, 0x8eU,
  0x8fU, 0x90U, 0x91U, 0x92U, 0x93U, 0x94U, 0x95U, 0x96U, 0x97U, 0x98U, 0x99U,
  0x9aU, 0x9bU, 0x9cU, 0x9dU, 0x9eU, 0x9fU, 0xa0U, 0xa1U, 0xa2U, 0xa3U, 0xa4U,
  0xa5U, 0xa6U, 0xa7U, 0xa8U, 0xa9U, 0xaaU, 0xabU, 0xacU, 0xadU, 0xaeU, 0xafU,
  0xb0U, 0xb1U, 0xb2U, 0xb3U, 0xb4U, 0xb5U, 0xb6U, 0xb7U, 0xb8U, 0xb9U, 0xbaU,
  0xbbU, 0xbcU, 0xbdU, 0xbeU, 0xbfU, 0xc0U, 0xc1U, 0xc2U, 0xc3U, 0xc4U, 0xc5U,
  0xc6U, 0xc7U, 0xc8U, 0xc9U, 0xcaU, 0xcbU, 0xccU, 0xcdU, 0xceU, 0xcfU, 0xd0U,
  0xd1U, 0xd2U, 0xd3U, 0xd4U, 0xd5U, 0xd6U, 0xd7U, 0xd8U, 0xd9U, 0xdaU, 0xdbU,
  0xdcU, 0xddU, 0xdeU, 0xdfU, 0xe0U, 0xe1U, 0xe2U, 0xe3U, 0xe4U, 0xe5U, 0xe6U,
  0xe7U, 0xe8U, 0xe9U, 0xeaU, 0xebU, 0xecU, 0xedU, 0xeeU, 0xefU, 0xf0U, 0xf1U,
  0xf2U, 0xf3U, 0xf4U, 0xf5U, 0xf6U, 0xf7U, 0xf8U, 0xf9U, 0xfaU, 0xfbU, 0xfcU,
  0xfdU, 0xfeU
};

static uint8_t key2s3[32] = { 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U,
                              0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
                              0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U,
                              0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU,
                              0x1cU, 0x1dU, 0x1eU, 0x1fU };

static uint8_t expected2s3[32] = {
  0x3fU, 0xb7U, 0x35U, 0x06U, 0x1aU, 0xbcU, 0x51U, 0x9dU, 0xfeU, 0x97U, 0x9eU,
  0x54U, 0xc1U, 0xeeU, 0x5bU, 0xfaU, 0xd0U, 0xa9U, 0xd8U, 0x58U, 0xb3U, 0x31U,
  0x5bU, 0xadU, 0x34U, 0xbdU, 0xe9U, 0x99U, 0xefU, 0xd7U, 0x24U, 0xddU
};

static uint8_t input2s4[251] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU,
  0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU,
  0x2cU, 0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3aU, 0x3bU, 0x3cU, 0x3dU, 0x3eU, 0x3fU, 0x40U, 0x41U,
  0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4aU, 0x4bU, 0x4cU,
  0x4dU, 0x4eU, 0x4fU, 0x50U, 0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U,
  0x58U, 0x59U, 0x5aU, 0x5bU, 0x5cU, 0x5dU, 0x5eU, 0x5fU, 0x60U, 0x61U, 0x62U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6aU, 0x6bU, 0x6cU, 0x6dU,
  0x6eU, 0x6fU, 0x70U, 0x71U, 0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U,
  0x79U, 0x7aU, 0x7bU, 0x7cU, 0x7dU, 0x7eU, 0x7fU, 0x80U, 0x81U, 0x82U, 0x83U,
  0x84U, 0x85U, 0x86U, 0x87U, 0x88U, 0x89U, 0x8aU, 0x8bU, 0x8cU, 0x8dU, 0x8eU,
  0x8fU, 0x90U, 0x91U, 0x92U, 0x93U, 0x94U, 0x95U, 0x96U, 0x97U, 0x98U, 0x99U,
  0x9aU, 0x9bU, 0x9cU, 0x9dU, 0x9eU, 0x9fU, 0xa0U, 0xa1U, 0xa2U, 0xa3U, 0xa4U,
  0xa5U, 0xa6U, 0xa7U, 0xa8U, 0xa9U, 0xaaU, 0xabU, 0xacU, 0xadU, 0xaeU, 0xafU,
  0xb0U, 0xb1U, 0xb2U, 0xb3U, 0xb4U, 0xb5U, 0xb6U, 0xb7U, 0xb8U, 0xb9U, 0xbaU,
  0xbbU, 0xbcU, 0xbdU, 0xbeU, 0xbfU, 0xc0U, 0xc1U, 0xc2U, 0xc3U, 0xc4U, 0xc5U,
  0xc6U, 0xc7U, 0xc8U, 0xc9U, 0xcaU, 0xcbU, 0xccU, 0xcdU, 0xceU, 0xcfU, 0xd0U,
  0xd1U, 0xd2U, 0xd3U, 0xd4U, 0xd5U, 0xd6U, 0xd7U, 0xd8U, 0xd9U, 0xdaU, 0xdbU,
  0xdcU, 0xddU, 0xdeU, 0xdfU, 0xe0U, 0xe1U, 0xe2U, 0xe3U, 0xe4U, 0xe5U, 0xe6U,
  0xe7U, 0xe8U, 0xe9U, 0xeaU, 0xebU, 0xecU, 0xedU, 0xeeU, 0xefU, 0xf0U, 0xf1U,
  0xf2U, 0xf3U, 0xf4U, 0xf5U, 0xf6U, 0xf7U, 0xf8U, 0xf9U, 0xfaU
};

static uint8_t key2s4[32] = { 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U,
                              0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU,
                              0x0eU, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U,
                              0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU,
                              0x1cU, 0x1dU, 0x1eU, 0x1fU };

static uint8_t expected2s4[32] = {
  0xd1U, 0x2bU, 0xf3U, 0x73U, 0x2eU, 0xf4U, 0xafU, 0x5cU, 0x22U, 0xfaU, 0x90U,
  0x35U, 0x6aU, 0xf8U, 0xfcU, 0x50U, 0xfcU, 0xb4U, 0x0fU, 0x8fU, 0x2eU, 0xa5U,
  0xc8U, 0x59U, 0x47U, 0x37U, 0xa3U, 0xb3U, 0xd5U, 0xabU, 0xdbU, 0xd7U
};

static uint8_t input2s8[64] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU,
  0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
  0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U,
  0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU,
  0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U,
  0x37U, 0x38U, 0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU
};

static uint8_t key2s8[32] = { 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U,
                              0x07U, 0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU,
                              0x0EU, 0x0FU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U,
                              0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU,
                              0x1CU, 0x1DU, 0x1EU, 0x1FU };

static uint8_t expected2s8[32] = {
  0x89U, 0x75U, 0xB0U, 0x57U, 0x7FU, 0xD3U, 0x55U, 0x66U, 0xD7U, 0x50U, 0xB3U,
  0x62U, 0xB0U, 0x89U, 0x7AU, 0x26U, 0xC3U, 0x99U, 0x13U, 0x6DU, 0xF0U, 0x7BU,
  0xABU, 0xABU, 0xBDU, 0xE6U, 0x20U, 0x3FU, 0xF2U, 0x95U, 0x4EU, 0xD4U
};

static blake2_test_vector vectors2b[] = {
  {
    .input = input2b1,
    .input_len = sizeof(input2b1) / sizeof(uint8_t),
    .key = key2b1,
    .key_len = sizeof(key2b1) / sizeof(uint8_t),
    .expected = expected2b1,
    .expected_len = sizeof(expected2b1) / sizeof(uint8_t),
  },
  {
    .input = input2b13,
    .input_len = sizeof(input2b13) / sizeof(uint8_t),
    .key = key2b13,
    .key_len = sizeof(key2b13) / sizeof(uint8_t),
    .expected = expected2b13,
    .expected_len = sizeof(expected2b13) / sizeof(uint8_t),
  }
};

static blake2_test_vector vectors2s[] = {
  {
    .input = input2s1,
    .input_len = sizeof(input2s1) / sizeof(uint8_t),
    .key = key2s1,
    .key_len = sizeof(key2s1) / sizeof(uint8_t),
    .expected = expected2s1,
    .expected_len = sizeof(expected2s1) / sizeof(uint8_t),
  },
  {
    .input = input2s2,
    .input_len = sizeof(input2s2) / sizeof(uint8_t),
    .key = key2s2,
    .key_len = sizeof(key2s2) / sizeof(uint8_t),
    .expected = expected2s2,
    .expected_len = sizeof(expected2s2) / sizeof(uint8_t),
  },
  {
    .input = input2s3,
    .input_len = sizeof(input2s3) / sizeof(uint8_t),
    .key = key2s3,
    .key_len = sizeof(key2s3) / sizeof(uint8_t),
    .expected = expected2s3,
    .expected_len = sizeof(expected2s3) / sizeof(uint8_t),
  },
  {
    .input = input2s4,
    .input_len = sizeof(input2s4) / sizeof(uint8_t),
    .key = key2s4,
    .key_len = sizeof(key2s4) / sizeof(uint8_t),
    .expected = expected2s4,
    .expected_len = sizeof(expected2s4) / sizeof(uint8_t),
  },
  {
    .input = input2s8,
    .input_len = sizeof(input2s8) / sizeof(uint8_t),
    .key = key2s8,
    .key_len = sizeof(key2s8) / sizeof(uint8_t),
    .expected = expected2s8,
    .expected_len = sizeof(expected2s8) / sizeof(uint8_t),
  }
};
