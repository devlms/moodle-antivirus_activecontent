@antivirus @antivirus_activecontent
Feature: Uploads with macros or scripts are refused
  In order to keep documents from running code on the computers that open them
  As an administrator
  I need Moodle to refuse uploads that carry macros or PDF scripts

  Background:
    Given the following config values are set as admin:
      | antiviruses | activecontent |

  Scenario: Both checks are on by default
    Given I log in as "admin"
    When I visit "/admin/settings.php?section=antivirussettingsactivecontent"
    Then the field "Refuse Office files with macros" matches value "1"
    And the field "Refuse PDFs with JavaScript or launch actions" matches value "1"

  @javascript
  Scenario: The administrator can turn a check off
    Given I log in as "admin"
    When I visit "/admin/settings.php?section=antivirussettingsactivecontent"
    And I set the field "Refuse PDFs with JavaScript or launch actions" to "0"
    And I press "Save changes"
    Then the field "Refuse PDFs with JavaScript or launch actions" matches value "0"
    And the field "Refuse Office files with macros" matches value "1"

  @javascript @_file_upload
  Scenario: A clean Word file still uploads with the blocker on
    Given I am on the "My private files" page logged in as "admin"
    When I upload "lib/antivirus/activecontent/tests/fixtures/essay.docx" file to "Files" filemanager
    Then I should see "1" elements in "Files" filemanager
    And I should see "essay.docx" in the "div.fp-content" "css_element"
