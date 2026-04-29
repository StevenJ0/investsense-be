const supabase = require('../../configs/supabase');

/**
 * Finds a user by their email address.
 * Used during login and registration duplicate-check.
 * @param {string} email
 * @returns {object|null} user row or null
 */
const findUserByEmail = async (email) => {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    // PGRST116 = "Row not found" – treat as a clean null, not an error
    if (error && error.code !== 'PGRST116') {
        throw new Error(`DB Error (findUserByEmail): ${error.message}`);
    }
    return data ?? null;
};

/**
 * Finds a user by their UUID primary key.
 * Used when validating a refresh token payload.
 * @param {string} id
 * @returns {object|null}
 */
const findUserById = async (id) => {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', id)
        .single();

    if (error && error.code !== 'PGRST116') {
        throw new Error(`DB Error (findUserById): ${error.message}`);
    }
    return data ?? null;
};

/**
 * Inserts a new user record.
 * Only stores the pre-hashed password — plaintext never touches the DB layer.
 * @param {object} param0 - { email, username, password_hash }
 * @returns {object} newly created user row
 */
const createUser = async ({ email, username, password_hash }) => {
    const { data, error } = await supabase
        .from('users')
        .insert([{ email, username, password_hash }])
        .select()
        .single();

    if (error) {
        throw new Error(`DB Error (createUser): ${error.message}`);
    }
    return data;
};

/**
 * Persists a new refresh token for a user (called on login & rotation).
 * Storing in DB enables one-time-use enforcement via rotation invalidation.
 * @param {string} userId
 * @param {string} refreshToken - hashed or raw token string
 */
const updateRefreshToken = async (userId, refreshToken) => {
    const { error } = await supabase
        .from('users')
        .update({ refresh_token: refreshToken })
        .eq('id', userId);

    if (error) {
        throw new Error(`DB Error (updateRefreshToken): ${error.message}`);
    }
};

/**
 * Clears the refresh token (sets to NULL) on logout.
 * This server-side invalidation prevents reuse of a stolen token.
 * @param {string} userId
 */
const clearRefreshToken = async (userId) => {
    const { error } = await supabase
        .from('users')
        .update({ refresh_token: null })
        .eq('id', userId);

    if (error) {
        throw new Error(`DB Error (clearRefreshToken): ${error.message}`);
    }
};

module.exports = {
    findUserByEmail,
    findUserById,
    createUser,
    updateRefreshToken,
    clearRefreshToken,
};
