<?php

namespace Drupal\ucb_directory_search;

use Psr\Log\LoggerInterface;

/**
 * CuDirectory Class.
 */
class DirectorySearch {
  /*
   * Attribute Declarations.
   */
  public $host = "directory.colorado.edu";
  public $base_dn = "ou=people,dc=colorado,dc=edu";
  public $ldap_attributes = [
    'cuedupersonuuid',
    'displayname',
    'title',
    'mail',
    'telephonenumber',
    'postaladdress',
    'cuedupersonhomedepartment',
    'edupersonprimaryaffiliation',
    'edupersonaffiliation',
    'cuedupersonschoolcollegename',
    'cuedupersonschoolcollegename2',
    'homephone',
    'labeleduri',
    'cuedupersonhighestdegree',
    'cuedupersonstatus',
    'cn',
    'cuedupersonplan',
    'cuedupersonsubplan',
  ];

  /*
   * Protected attributes.
   */
  protected $return_count = 0;
  protected $hard_return_count = 0;
  protected $authenticated = FALSE;
  protected $more_results = FALSE;
  protected $user_type_filter = 'all';
  protected $bind_dn = FALSE;
  protected $bind_password = FALSE;
  protected $last_query_error = FALSE;

  /**
   * The current LDAP connection.
   *
   * @var \LDAP\Connection|false
   */
  protected $connection = FALSE;

  /**
   * The logger channel for this module.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * Constructs the Article Syndication service.
   *
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger channel for this module.
   */
  public function __construct(LoggerInterface $logger) {
    $this->logger = $logger;
  }

  /**
   * Formulates an LDAP query string.
   *
   * @return string
   *   The LDAP query string.
   */
  protected function cu_directory_ldap_lookup($type, $q, $wc_q, $affiliation = NULL) {
    if (is_numeric($q)) {
      return "(cuedupersonuuid=$q)";
    }
    else {
      $query = $type == 'wc_q' ? $wc_q : $q;
      if ($affiliation != NULL) {
        return "(&(cn=$query)(eduPersonAffiliation=$affiliation))";
      }
      else {
        return "(cn=$query)";
      }
    }
  }

  /**
   * Perform the search.
   *
   * @param $q
   *   The query string
   *
   * @return array
   *   Returns an array of search results
   */
  public function search($q) {
    // Eliminate obvious queries that won't return LDAP results.
    if (!$this->ldapWhitelistSearch($q)) {
      return [];
    }

    /* Build the connection if we have to */
    if (!$this->connection) {
      if (!$this->connect()) {
        return FALSE;
      }
    }

    // Return an empty array if the query string is empty.
    if (empty($q)) {
      return [];
    }

    // Sanitize the query string.
    // @NOTE The ldapEscapeFilter needs to be vetted and likely needs some work, Kris can help
    $q = $this->ldapEscapeFilter($q);
    $wc_q = $this->ldapWildcard($q);

    // @NOTE Kris can help with the filters we need
    // Set the filter based on what type of user we're returning
    switch ($this->user_type_filter) {
      // Students.
      case 'student':
        $wc_filter = $this->cu_directory_ldap_lookup('wc_q', $q, $wc_q, 'student');
        $filter = $this->cu_directory_ldap_lookup('q', $q, $wc_q, 'student');
        break;

      // Faculty and Staff.
      case 'facstaff':
        $wc_filter = $this->cu_directory_ldap_lookup('wc_q', $q, $wc_q, 'employee');
        $filter = $this->cu_directory_ldap_lookup('q', $q, $wc_q, 'employee');
        break;

      // Default is all.
      default:
        $wc_filter = $this->cu_directory_ldap_lookup('wc_q', $q, $wc_q);
        $filter = $this->cu_directory_ldap_lookup('q', $q, $wc_q);
    }

    // Try the search with wildcards. If we return too many results, we'll try again without
    // any wildcards.
    // Reset the last query error.
    $this->last_query_error = FALSE;

    // ldap_ functions throw warnings and not Exceptions
    // Temporarily use ::lastQueryErrorHandler.
    set_error_handler([&$this, 'lastQueryErrorHandler']);

    // Perform the search using the defined wildcard filter.
    $search_type = 'fuzzy';
    $ldap_search = ldap_search($this->connection, $this->base_dn, $wc_filter, $this->ldap_attributes, FALSE, $this->hard_return_count);

    // Retore the previously set error handler from ::lastQueryErrorHandler.
    restore_error_handler();

    // If we recieved too many results with the wildcard search, try again without wildcards.
    if ($this->last_query_error == 'Too Many Results') {
      // If the error before was too many, we'll search without wildcards, but continue
      // to spit the "Too many results" if we get nothing back without wildcards.
      // We must first reset the error handler to clear out the previous error.
      // Reset the last query error.
      $this->last_query_error = FALSE;

      // ldap_ functions throw warnings and not Exceptions
      // Temporarily use ::lastQueryErrorHandler.
      set_error_handler([&$this, 'lastQueryErrorHandler']);

      // Perform the search using the defined filter.
      $ldap_search = ldap_search($this->connection, $this->base_dn, $filter, $this->ldap_attributes, FALSE, $this->hard_return_count);

      // Retore the previously set error handler from ::lastQueryErrorHandler.
      restore_error_handler();

      // Set a var to indicate that this is a nonfuzzy search. This will help us determine which error message to display later.
      $search_type = 'nonfuzzy';
    }

    // Pull the results and clear the search from memory.
    $res = ldap_get_entries($this->connection, $ldap_search);
    $num_results = ldap_count_entries($this->connection, $ldap_search);
    ldap_free_result($ldap_search);

    $data = [];
    foreach ($res as $item) {
      if (!empty($item['cuedupersonuuid'])) {
        $data[] = $this->formatResults($item);
      }
    }

    // Filter the array to only include the return_count if a return_count is specified.
    if ($this->return_count && $num_results) {
      $chunked_data = array_chunk($data, $this->return_count);
      $data = $chunked_data[0];
    }

    /** @NOTE Sorting can go here, we can usort with a custom function **/
    return [
      'data' => $data,
      'return_count' => count($data),
      'total_results' => $num_results,
      'error' => $this->last_query_error,
      'search_type' => $search_type,
    ];
  }

  /**
   * Find and return a record by uuid.
   *
   * @param $uuid
   *   The uuid to search for
   *
   * @return array|false
   *   Will return a formatted array or FALSE.
   */
  public function find($uuid) {
    /* Build the connection if we have to */
    if (!$this->connection) {
      if (!$this->connect()) {
        return FALSE;
      }
    }

    $uuid = (int) $uuid;
    $filter = "(cuEduPersonUUID=$uuid)";
    $ldap_search = ldap_search($this->connection, $this->base_dn, $filter, $this->ldap_attributes, FALSE);
    $num_results = @ldap_count_entries($this->connection, $ldap_search);
    if ($num_results === 1) {
      $res = ldap_get_entries($this->connection, $ldap_search);
      ldap_free_result($ldap_search);
      return $this->formatResults($res[0]);
    }
    else {
      return FALSE;
    }
  }

  /**
   * Set the class attribute for limiting the number of results returned.
   *
   * @param $int
   *   The integer to limit the results by
   *
   * @return int
   *   Returns the value $this->return_count was set to
   */
  public function returnCount($int) {
    // Cast as an integer.
    $int = (int) $int;
    // If it's less than 0, make it 0.
    if ($int < 0) {
      $int = 0;
    }
    // Set the class attribute.
    $this->return_count = $int;
    // Return what was set.
    return $int;
  }

  /**
   * Set the class attribute for limiting the number of results returned by ldap_search.
   *
   * @param $int
   *   The integer to limit the results by
   *
   * @return int
   *   Returns the value $this->return_count was set to
   */
  public function hardReturnCount($int) {
    // Cast as an integer.
    $int = (int) $int;
    // If it's less than 0, make it 0.
    if ($int < 0) {
      $int = 0;
    }
    // Set the class attribute.
    $this->hard_return_count = $int;
    // Return what was set.
    return $int;
  }

  /**
   * Set the user filter.
   *
   * @param $user_type
   *   The user type to filter by, acceptable values are enforced
   *
   * @return string|false
   *   Returns either the value that gets set or FALSE
   */
  public function userTypeFilter($user_type) {
    $user_type = strtolower($user_type);
    $accepted_user_types = ['all', 'student', 'facstaff'];
    if (in_array($user_type, $accepted_user_types)) {
      $this->user_type_filter = $user_type;
      return $this->user_type_filter;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Set an account to bind as for non-anonymous searches.
   *
   * @param $bind_dn
   *   The dn to bind as
   * @param $bind_password
   *   The password to use
   *
   * @return bool
   *   Will return TRUE or FALSE.
   */
  public function setBindAccount($bind_dn, $bind_password) {
    if (!empty($bind_dn) && !empty($bind_password)) {
      $this->bind_dn = $bind_dn;
      $this->bind_password = $bind_password;
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Returns the more_results attribute.
   *
   * More_results will be set to TRUE if ldap_search was given a return limit
   * and threw a warning.
   *
   * @return bool
   *   Returns the value of $this->more_results
   */
  public function areMoreResults() {
    return $this->more_results;
  }

  /**
   * Unbind the current connection, if there is a current connection.
   *
   * @return bool
   *   returns TRUE or FALSE
   */
  public function close() {
    if ($this->connection) {
      ldap_unbind($this->connection);
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Format a single ldap_search result record into a standardized associative array.
   *
   * @param $res
   *   A single ldap_get_entries record
   *
   * @return array
   *   A formatted array of the input
   */
  protected function formatResults($res) {
    $out = [];
    // Cleanup and add attributes.
    $out['uuid']                = $this->getAttr($res, 'cuedupersonuuid');
    $out['name']                = $this->getAttr($res, 'displayname');
    $out['title']               = $this->getAttr($res, 'title');
    $out['email']               = $this->getAttr($res, 'mail');
    $out['phone']               = $this->getAttr($res, 'telephonenumber');
    $out['address']             = $this->getAttr($res, 'postaladdress');
    $out['dept']                = $this->getAttr($res, 'cuedupersonhomedepartment');
    $out['primary_affiliation'] = $this->getAttr($res, 'edupersonprimaryaffiliation');
    // Colleges.
    $out['cuedupersonschoolcollegename']  = $this->getAttr($res, 'cuedupersonschoolcollegename');
    $out['cuedupersonschoolcollegename2'] = $this->getAttr($res, 'cuedupersonschoolcollegename2');
    // Majors.
    $out['cuedupersonplan'] = $this->getAttr($res, 'cuedupersonplan');
    // Minors.
    $out['cuedupersonsubplan'] = $this->getAttr($res, 'cuedupersonsubplan');

    // Add affiliations.
    $affiliations = [];
    if (!empty($res['edupersonaffiliation'])) {
      foreach ($res['edupersonaffiliation'] as $key => $affiliation) {
        if ($key !== "count") {
          $affiliations[] = $affiliation;
        }
      }
    }
    $out['affiliations'] = $affiliations;

    // Set Majors
    // The recent directory changes seem to only output a single major, but let's
    // make this work just in case they pass us an array for if a person has
    // a double major for example.
    if (is_array($out['cuedupersonplan'])) {
      sort($out['cuedupersonplan']);
      $out['majors'] = implode(', ', $out['cuedupersonplan']);
    }
    else {
      $out['majors'] = $out['cuedupersonplan'];
    }

    // Add all names / cn's.
    $names = [];
    if (!empty($res['cn'])) {
      foreach ($res['cn'] as $key => $name_instance) {
        if ($key !== "count") {
          $names[] = $name_instance;
        }
      }
    }
    $out['names'] = $names;

    return $out;
  }

  /**
   * Try a result for a key and return [0] or default
   * This should clean up the ::formatResults() code
   */
  protected function getAttr($res, $a, $default = '') {
    return !empty($res[$a]) ? $res[$a][0] : $default;
  }

  /**
   * Build the LDAP connection.
   *
   * @return bool
   *   Returns TRUE or FALSE depending on whether or not a connection was successfully made
   */
  protected function connect() {
    /* Make the connection suppressing any errors.
    The function should still return FALSE if it can't connect */
    $connection = @ldap_connect('ldaps://' . $this->host);
    if ($connection) {
      // We connected, see if we're meant to attempt a non-anonymous bind.
      if ($this->bind_dn) {
        $bind_attempt = @ldap_bind($connection, $this->bind_dn, $this->bind_password);
        // If the bind didn't work, free the connection and return FALSE.
        if (!$bind_attempt) {
          $this->logger->error('Failed to bind to LDAP.');
          @ldap_unbind($connection);
          return FALSE;
        }
      }
      $this->connection = $connection;
      return TRUE;
    }
    else {
      $this->logger->error('Failed to connect to LDAP.');
      $this->connection = FALSE;
      return FALSE;
    }
  }

  /**
   * Determines if the search string is valid.
   *
   * @param string $str
   *   The search string.
   *
   * @return bool
   *   Returns TRUE if search string contains valid characters a-zA-Z- ,
   *   is not one of the top search results that we know isnt in ldap,
   *   and does not contain more than 4 words.
   */
  protected function ldapWhitelistSearch($str) {
    $top_results = [
      'calendar',
      'academic calendar',
      'housing',
      'culink',
      'bookstore',
      'tuition',
      'mycuinfo',
      'jobs',
      'employment',
      'bursar',
      'orientation',
      'registrar',
      'transcripts',
      'library',
      'parking',
      'email',
      'cu link',
      'financial aid',
      'rec center',
      'book store',
      'directory',
      'human resources',
      'study abroard',
      'career services',
      'campus map',
      'oit',
      'nursing',
    ];

    if (in_array($str, $top_results)) {
      return FALSE;
    }

    // If it contains more than 4 words.
    if (str_word_count($str) > 4) {
      return FALSE;
    }

    // Only allow the following set of characters.
    if (preg_match("/^[a-zA-Z0-9-_'` ]*$/", $str) != 1) {
      return FALSE;
    }

    return TRUE;
  }

  /**
   * Escapes a string for an LDAP filter.
   *
   * @param string $str
   *   The string to be escaped
   *
   * @return string
   *   Returns an escaped version of $str
   */
  protected function ldapEscapeFilter($str) {
    $metaChars = ['\\', '(', ')', '#', '*'];
    $quotedMetaChars = [];
    foreach ($metaChars as $key => $value) {
      $quotedMetaChars[$key] = '\\' . dechex(ord($value));
    }
    // Replace them.
    $str = str_replace($metaChars, $quotedMetaChars, $str);
    return ($str);
  }

  /**
   * Replaces spaces with wildcard character and adds one to the end.
   *
   * @return string
   */
  protected function ldapWildcard($str) {
    return str_replace(' ', '*', $str) . '*';
  }

  /**
   * Temporary error handler to catch the PHP warning from
   * ldap_search (Bad PHP)
   *
   * Standard PHP error handler callback inputs
   * http://php.net/manual/en/function.set-error-handler.php.
   */
  protected function lastQueryErrorHandler($errno, $errstr) {
    // Looking for a specific error we can give a nice name to,
    // otherwise just set it as the error string.
    $error = preg_match('/adminlimit exceeded/i', $errstr) ? 'Too Many Results' : $errstr;
    $this->last_query_error = $error;
    return $errno;
  }

}
