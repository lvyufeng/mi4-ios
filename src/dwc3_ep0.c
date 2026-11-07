/* Original implementation from wire-level requirements, not vendor functions. */
#include "dwc3_ep0.h"

static const uint8_t fixture_device[] = {
    18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 1, 0, 0, 1, 0, 1, 0, 1
};
static const uint8_t fixture_config[] = {
    9, 2, 25, 0, 1, 1, 0, 0x80, 50,
    9, 4, 0, 0, 1, 0xff, 0, 0, 0,
    7, 5, 0x81, 2, 0, 2, 0
};
static const uint8_t fixture_languages[] = {4, 3, 9, 4};
static const uint8_t fixture_product[] = {
    16, 3, 'O', 0, 'f', 0, 'f', 0, 'l', 0, 'i', 0, 'n', 0, 'e', 0
};
const struct dwc3_ep0_descriptor dwc3_ep0_fixture[4] = {
    {1, 0, 0, fixture_device, sizeof fixture_device},
    {2, 0, 0, fixture_config, sizeof fixture_config},
    {3, 0, 0, fixture_languages, sizeof fixture_languages},
    {3, 1, 0x0409, fixture_product, sizeof fixture_product}
};

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static const struct dwc3_ep0_descriptor *lookup(const struct dwc3_ep0 *ep,
    uint8_t type, uint8_t index, uint16_t language)
{
    size_t i;
    for (i = 0; i < ep->descriptor_count; ++i) {
        const struct dwc3_ep0_descriptor *d = &ep->descriptors[i];
        if (d->type == type && d->index == index && d->language == language)
            return d;
    }
    return NULL;
}

static bool descriptor_valid(const struct dwc3_ep0_descriptor *d)
{
    const uint8_t *b = d->bytes;
    if (!b || d->length < 2 || d->length > DWC3_EP0_MAX_DESCRIPTOR_BYTES ||
        b[1] != d->type)
        return false;
    if (d->type == 1)
        return d->index == 0 && d->language == 0 && d->length == 18 &&
            b[0] == 18 && le16(b + 2) == 0x0200 && b[4] == 0 &&
            b[5] == 0 && b[6] == 0 && b[7] == 64 && b[17] == 1;
    if (d->type == 2) {
        if (d->index || d->language || d->length != 25 || b[0] != 9)
            return false;
        return le16(b + 2) == d->length && b[4] == 1 && b[5] == 1 &&
            b[6] == 0 && (b[7] == 0x80 || b[7] == 0xc0) &&
            b[9] == 9 && b[10] == 4 && b[11] == 0 && b[12] == 0 &&
            b[13] == 1 && b[14] == 0xff && b[15] == 0 && b[16] == 0 &&
            b[17] == 0 && b[18] == 7 && b[19] == 5 && b[20] == 0x81 &&
            b[21] == 2 && le16(b + 22) == 512 && b[24] == 0;
    }
    return d->type == 3 && d->length <= 254 && d->length % 2 == 0 &&
        b[0] == d->length && (d->index ? d->language != 0 :
                            d->language == 0 && d->length >= 4);
}

bool dwc3_ep0_init(struct dwc3_ep0 *ep,
                  const struct dwc3_ep0_descriptor *table, size_t count)
{
    size_t i, j;
    const struct dwc3_ep0_descriptor *langs, *dev;
    if (!ep)
        return false;
    *ep = (struct dwc3_ep0){0};
    if (!table || !count || count > DWC3_EP0_MAX_DESCRIPTORS)
        return false;
    for (i = 0; i < count; ++i) {
        if (!descriptor_valid(&table[i]))
            return false;
        for (j = 0; j < i; ++j)
            if (table[i].type == table[j].type &&
                table[i].index == table[j].index &&
                table[i].language == table[j].language)
                return false;
    }
    ep->descriptors = table;
    ep->descriptor_count = count;
    dev = lookup(ep, 1, 0, 0);
    langs = lookup(ep, 3, 0, 0);
    if (!dev || !lookup(ep, 2, 0, 0) || !langs)
        goto invalid;
    for (i = 0; i < count; ++i) {
        if (table[i].type != 3 || table[i].index == 0)
            continue;
        for (j = 2; j < langs->length; j += 2)
            if (le16(langs->bytes + j) == table[i].language)
                break;
        if (j == langs->length)
            goto invalid;
    }
    for (i = 14; i <= 16; ++i)
        if (dev->bytes[i] && !lookup(ep, 3, dev->bytes[i],
                                    le16(langs->bytes + 2)))
            goto invalid;
    return true;
invalid:
    *ep = (struct dwc3_ep0){0};
    return false;
}

static void cancel(struct dwc3_ep0 *ep)
{
    ep->pending = DWC3_EP0_PENDING_NONE;
    ep->pending_value = 0;
    if (ep->phase != DWC3_EP0_UNRESET)
        ep->phase = DWC3_EP0_IDLE;
}

void dwc3_ep0_bus_reset(struct dwc3_ep0 *ep)
{
    if (!ep)
        return;
    cancel(ep);
    if (ep->transaction != UINT64_MAX)
        ++ep->transaction;
    ep->address = 0;
    ep->configuration = 0;
    if (ep->descriptor_count)
        ep->phase = DWC3_EP0_IDLE;
}

struct dwc3_ep0_in_shape dwc3_ep0_shape_in(size_t available, uint16_t requested)
{
    struct dwc3_ep0_in_shape s = {0};
    s.length = available < requested ? available : requested;
    s.data_stage = requested != 0;
    s.data_zlp = available < requested &&
        available % DWC3_EP0_MAX_PACKET == 0;
    s.status_direction = requested ? DWC3_EP0_OUT : DWC3_EP0_IN;
    return s;
}

static struct dwc3_ep0_plan stall(const struct dwc3_ep0 *ep)
{
    struct dwc3_ep0_plan p = {0};
    p.action = DWC3_EP0_STALL;
    p.transaction = ep ? ep->transaction : 0;
    return p;
}

static struct dwc3_ep0_plan status_in(struct dwc3_ep0 *ep)
{
    struct dwc3_ep0_plan p = stall(ep);
    ep->phase = DWC3_EP0_STATUS_PHASE_IN;
    p.action = DWC3_EP0_STATUS_IN;
    p.status_direction = DWC3_EP0_IN;
    p.pending = ep->pending;
    p.pending_value = ep->pending_value;
    return p;
}

static struct dwc3_ep0_plan data_in(struct dwc3_ep0 *ep, const uint8_t *bytes,
                                   size_t available, uint16_t requested)
{
    struct dwc3_ep0_in_shape s = dwc3_ep0_shape_in(available, requested);
    struct dwc3_ep0_plan p = stall(ep);
    if (!s.data_stage)
        return status_in(ep);
    ep->phase = DWC3_EP0_DATA;
    p.action = DWC3_EP0_DATA_IN;
    p.status_direction = s.status_direction;
    p.data = bytes;
    p.length = s.length;
    p.data_zlp = s.data_zlp;
    return p;
}

struct dwc3_ep0_plan dwc3_ep0_setup(struct dwc3_ep0 *ep,
                                  const uint8_t *s, size_t length)
{
    uint16_t value, index, requested;
    uint8_t type, number, bm;
    const struct dwc3_ep0_descriptor *d;
    if (!ep)
        return stall(NULL);
    cancel(ep); /* Every new SETUP aborts old pending state, even if invalid. */
    if (ep->transaction == UINT64_MAX)
        return stall(ep);
    ++ep->transaction;
    if (ep->phase == DWC3_EP0_UNRESET || !ep->descriptor_count ||
        !s || length != 8)
        return stall(ep);
    value = le16(s + 2);
    index = le16(s + 4);
    requested = le16(s + 6);
    bm = requested ? s[0] : (uint8_t)(s[0] & 0x7fu);
    switch (s[1]) {
    case 6: /* GET_DESCRIPTOR: no-data direction bit is ignored by USB 9.3.1. */
        if (requested ? bm != 0x80 : bm != 0)
            break;
        type = (uint8_t)(value >> 8);
        number = (uint8_t)value;
        if ((type != 1 && type != 2 && type != 3) ||
            (type != 3 && (index || number)) ||
            (type == 3 && number == 0 && index != 0))
            break;
        d = lookup(ep, type, number, index);
        if (d)
            return data_in(ep, d->bytes, d->length, requested);
        break;
    case 5: /* SET_ADDRESS: prohibited while configured. */
        if (bm || value > 127 || index || requested || ep->configuration)
            break;
        ep->pending = DWC3_EP0_PENDING_ADDRESS;
        ep->pending_value = (uint8_t)value;
        return status_in(ep);
    case 9: /* SET_CONFIGURATION: zero legal only Address/Configured state. */
        if (bm || value > 1 || index || requested || !ep->address)
            break;
        ep->pending = DWC3_EP0_PENDING_CONFIG;
        ep->pending_value = (uint8_t)value;
        return status_in(ep);
    case 8: /* GET_CONFIGURATION */
        if (s[0] != 0x80 || value || index || requested != 1 || !ep->address)
            break;
        ep->reply[0] = ep->configuration;
        return data_in(ep, ep->reply, 1, requested);
    case 0: /* GET_STATUS: device/interface/EP0 only; bulk halt deferred. */
        if (value || requested != 2 || !ep->address)
            break;
        ep->reply[0] = 0;
        ep->reply[1] = 0;
        if (s[0] == 0x80 && index == 0) {
            d = lookup(ep, 2, 0, 0);
            ep->reply[0] = (uint8_t)((d->bytes[7] >> 6) & 1u);
        } else if (!(s[0] == 0x81 && index == 0 && ep->configuration) &&
                   !(s[0] == 0x82 && (index == 0 || index == 0x80))) {
            break;
        }
        return data_in(ep, ep->reply, 2, requested);
    case 10: /* GET_INTERFACE: one interface, fixed alt zero. */
        if (s[0] != 0x81 || value || index || requested != 1 ||
            !ep->configuration)
            break;
        ep->reply[0] = 0;
        return data_in(ep, ep->reply, 1, requested);
    case 11: /* SET_INTERFACE: no endpoint action is implied here. */
        if (bm != 0x01 || value || index || requested || !ep->configuration)
            break;
        return status_in(ep);
    default: /* Includes CLEAR/SET_FEATURE and every nonstandard request. */
        break;
    }
    return stall(ep);
}

struct dwc3_ep0_plan dwc3_ep0_data_complete(struct dwc3_ep0 *ep,
    uint64_t transaction, enum dwc3_ep0_direction direction, bool success)
{
    struct dwc3_ep0_plan p = stall(ep);
    if (!ep || transaction != ep->transaction)
        return p;
    if (ep->phase != DWC3_EP0_DATA || direction != DWC3_EP0_IN || !success) {
        cancel(ep);
        return p;
    }
    ep->phase = DWC3_EP0_STATUS_PHASE_OUT;
    p.action = DWC3_EP0_STATUS_OUT;
    p.status_direction = DWC3_EP0_OUT;
    return p;
}

bool dwc3_ep0_status_complete(struct dwc3_ep0 *ep, uint64_t transaction,
                            enum dwc3_ep0_direction direction, bool success)
{
    bool in, out;
    if (!ep || transaction != ep->transaction)
        return false;
    in = ep->phase == DWC3_EP0_STATUS_PHASE_IN && direction == DWC3_EP0_IN;
    out = ep->phase == DWC3_EP0_STATUS_PHASE_OUT && direction == DWC3_EP0_OUT;
    if ((!in && !out) || !success) {
        cancel(ep);
        return false;
    }
    if (ep->pending == DWC3_EP0_PENDING_ADDRESS)
        ep->address = ep->pending_value;
    if (ep->pending == DWC3_EP0_PENDING_CONFIG)
        ep->configuration = ep->pending_value;
    cancel(ep);
    return true;
}
