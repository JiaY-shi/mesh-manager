// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <ucode/module.h>

#define DEPTH_LIMIT 256
#define NODE_LIMIT (1024 * 1024)
#define BYTE_LIMIT (8 * 1024 * 1024)

struct comparison {
	uc_value_t *left[DEPTH_LIMIT];
	uc_value_t *right[DEPTH_LIMIT];
	size_t nodes;
	size_t bytes;
};

static bool scalar(uc_type_t type)
{
	return type == UC_NULL || type == UC_BOOLEAN || type == UC_INTEGER ||
	       type == UC_DOUBLE || type == UC_STRING;
}

static bool numeric_json_equal(uc_value_t *left, uc_value_t *right)
{
	/* Preserve ucode's JSON number formatting, including -0.0 and nonfinite values. */
	char *a = ucv_to_jsonstring(NULL, left), *b = ucv_to_jsonstring(NULL, right);
	bool result = a && b && !strcmp(a, b);
	free(a);
	free(b);
	return result;
}

static bool compare(struct comparison *state, uc_value_t *left, uc_value_t *right, size_t depth)
{
	uc_type_t type = ucv_type(left), other = ucv_type(right);
	size_t length;
	bool found;

	if (++state->nodes > NODE_LIMIT || depth >= DEPTH_LIMIT)
		return false;
	if ((type == UC_DOUBLE && other == UC_STRING) || (other == UC_DOUBLE && type == UC_STRING)) {
		length = ucv_string_length(type == UC_STRING ? left : right);
		if (length > BYTE_LIMIT - state->bytes)
			return false;
		state->bytes += length;
	}
	if (type == UC_DOUBLE && scalar(other))
		return numeric_json_equal(left, right);
	if (other == UC_DOUBLE && scalar(type))
		return numeric_json_equal(left, right);
	if (type != other)
		return false;

	switch (type) {
	case UC_NULL:
		return true;
	case UC_BOOLEAN:
		return ucv_boolean_get(left) == ucv_boolean_get(right);
	case UC_INTEGER:
		return ucv_is_equal(left, right);
	case UC_STRING:
		length = ucv_string_length(left);
		if (length != ucv_string_length(right) || length > BYTE_LIMIT - state->bytes)
			return false;
		state->bytes += length;
		return !memcmp(ucv_string_get(left), ucv_string_get(right), length);
	case UC_ARRAY:
	case UC_OBJECT:
		break;
	default:
		return false;
	}

	/* Even identical objects must be traversed so cycles and unsupported children fail closed. */
	for (size_t i = 0; i < depth; i++)
		if (state->left[i] == left || state->right[i] == right)
			return false;
	state->left[depth] = left;
	state->right[depth] = right;
	if (type == UC_ARRAY) {
		length = ucv_array_length(left);
		if (length != ucv_array_length(right) || length > NODE_LIMIT - state->nodes)
			return false;
		for (size_t i = 0; i < length; i++)
			if (!compare(state, ucv_array_get(left, i), ucv_array_get(right, i), depth + 1))
				return false;
		return true;
	}
	length = ucv_object_length(left);
	if (length != ucv_object_length(right) || length > NODE_LIMIT - state->nodes)
		return false;
	ucv_object_foreach(left, key, value) {
		size_t bytes = strlen(key);
		if (bytes > BYTE_LIMIT - state->bytes)
			return false;
		state->bytes += bytes;
		uc_value_t *actual = ucv_object_get(right, key, &found);
		if (!found || !compare(state, value, actual, depth + 1))
			return false;
	}
	return true;
}

static uc_value_t *equal(uc_vm_t *vm, size_t nargs)
{
	struct comparison state = { 0 };
	return ucv_boolean_new(nargs == 2 && compare(&state, uc_fn_arg(0), uc_fn_arg(1), 0));
}

struct copying {
	uc_vm_t *vm;
	uc_value_t *ancestors[DEPTH_LIMIT];
	size_t nodes, bytes;
	bool failed;
};

/* Copy containers, retain immutable scalars. Never round-trip secrets through
 * a serializer, retain mutable aliases, or silently truncate an oversized tree. */
static uc_value_t *copy_value(struct copying *s, uc_value_t *value, size_t depth)
{
	uc_type_t type = ucv_type(value);
	uc_value_t *out, *child;
	size_t length;
	if (++s->nodes > NODE_LIMIT || depth >= DEPTH_LIMIT)
		goto fail;
	if (type == UC_STRING) {
		length = ucv_string_length(value);
		if (length > BYTE_LIMIT - s->bytes)
			goto fail;
		s->bytes += length;
	}
	if (scalar(type))
		return ucv_get(value);
	if (type != UC_ARRAY && type != UC_OBJECT)
		goto fail;
	for (size_t i = 0; i < depth; i++)
		if (s->ancestors[i] == value)
			goto fail;
	s->ancestors[depth] = value;
	out = type == UC_ARRAY ? ucv_array_new(s->vm) : ucv_object_new(s->vm);
	if (type == UC_ARRAY) {
		length = ucv_array_length(value);
		if (length > NODE_LIMIT - s->nodes)
			goto fail_out;
		for (size_t i = 0; i < length; i++) {
			child = copy_value(s, ucv_array_get(value, i), depth + 1);
			if (s->failed)
				goto fail_out;
			ucv_array_push(out, child);
		}
	} else {
		if (ucv_object_length(value) > NODE_LIMIT - s->nodes)
			goto fail_out;
		ucv_object_foreach(value, key, item) {
			length = strlen(key);
			if (length > BYTE_LIMIT - s->bytes)
				goto fail_out;
			s->bytes += length;
			child = copy_value(s, item, depth + 1);
			if (s->failed)
				goto fail_out;
			ucv_object_add(out, key, child);
		}
	}
	return out;
fail_out:
	ucv_put(out);
fail:
	s->failed = true;
	return NULL;
}

static uc_value_t *copy_json(uc_vm_t *vm, size_t nargs)
{
	struct copying s = { .vm = vm };
	uc_value_t *out = nargs == 1 ? copy_value(&s, uc_fn_arg(0), 0) : NULL;
	if (nargs != 1 || s.failed)
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid or oversized JSON value");
	return out;
}

static uc_value_t *uci_sections(uc_vm_t *vm, size_t nargs)
{
	struct copying s = { .vm = vm };
	uc_value_t *source = uc_fn_arg(0), *out = ucv_object_new(vm), *section, *values, *child, *name, *type;
	if (nargs != 1 || ucv_type(source) != UC_OBJECT || ucv_object_length(source) > NODE_LIMIT)
		goto fail;
	ucv_object_foreach(source, key, item) {
		if (ucv_type(item) != UC_OBJECT)
			goto fail;
		name = ucv_object_get(item, ".name", NULL);
		type = ucv_object_get(item, ".type", NULL);
		if (ucv_type(name) != UC_STRING || ucv_type(type) != UC_STRING ||
		    ucv_string_length(name) != strlen(key) || strcmp(ucv_string_get(name), key))
			goto fail;
		section = ucv_object_new(vm);
		values = ucv_object_new(vm);
		ucv_object_add(out, key, section);
		ucv_object_add(section, "type", ucv_get(type));
		ucv_object_add(section, "values", values);
		s.bytes += strlen(key) + ucv_string_length(type);
		if (s.bytes > BYTE_LIMIT || ++s.nodes > NODE_LIMIT)
			goto fail;
		ucv_object_foreach(item, option, value) {
			if (option[0] == '.')
				continue;
			size_t length = strlen(option);
			if (length > BYTE_LIMIT - s.bytes)
				goto fail;
			s.bytes += length;
			child = copy_value(&s, value, 0);
			if (s.failed)
				goto fail;
			ucv_object_add(values, option, child);
		}
	}
	return out;
fail:
	ucv_put(out);
	uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid or oversized UCI sections");
	return NULL;
}

static const uc_function_list_t functions[] = {
	{ "equal", equal }, { "copy_json", copy_json }, { "uci_sections", uci_sections }
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	(void)vm;
	uc_function_list_register(scope, functions);
}
