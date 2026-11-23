<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

namespace antivirus_activecontent;

/**
 * Tests for the active content scanner.
 *
 * @package    antivirus_activecontent
 * @copyright  2026 DevLMS
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \antivirus_activecontent\scanner
 */
final class scanner_test extends \advanced_testcase {
    /**
     * Write content to a temp file.
     *
     * @param string $content
     * @return string path
     */
    private function file(string $content): string {
        $path = make_request_directory() . '/upload';
        file_put_contents($path, $content);
        return $path;
    }

    /**
     * An Office Open XML file (docx, xlsx, pptx) with the given extra entries.
     *
     * @param array $entries name => content
     * @param string $contenttype main content type
     * @return string path
     */
    private function ooxml(
        array $entries = [],
        string $contenttype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
    ): string {
        $path = make_request_directory() . '/doc.zip';
        $zip = new \ZipArchive();
        $zip->open($path, \ZipArchive::CREATE);
        $zip->addFromString('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/' .
            'package/2006/content-types"><Override PartName="/word/document.xml" ContentType="' . $contenttype . '"/></Types>');
        $zip->addFromString('word/document.xml', '<w:document><w:body><w:p>Essay</w:p></w:body></w:document>');
        foreach ($entries as $name => $content) {
            $zip->addFromString($name, $content);
        }
        $zip->close();
        return $path;
    }

    /**
     * A minimal PDF with the given catalog extras and objects.
     *
     * @param string $extra
     * @return string
     */
    private function pdf(string $extra = ''): string {
        return "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R $extra >>\nendobj\n" .
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    }

    /**
     * Scan with default settings.
     *
     * @param string $path
     * @param string $filename
     * @return array [result, notice]
     */
    private function scan(string $path, string $filename = 'homework'): array {
        $scanner = new scanner();
        $result = $scanner->scan_file($path, $filename);
        return [$result, $scanner->get_scanning_notice()];
    }

    public function test_clean_files_pass(): void {
        $this->resetAfterTest();
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->ooxml(), 'essay.docx')[0]);
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file($this->pdf()), 'notes.pdf')[0]);
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file('Just text, mentions /JavaScript'), 'a.txt')[0]);
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file(''), 'empty')[0]);
    }

    public function test_office_file_with_a_macro_project_is_found_whatever_its_name(): void {
        $this->resetAfterTest();
        $path = $this->ooxml(['word/vbaProject.bin' => "\xD0\xCF\x11\xE0 macro bytes"]);
        [$result, $notice] = $this->scan($path, 'essay.docx');
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $result);
        $this->assertStringContainsString('macro', $notice);
    }

    public function test_macro_enabled_content_type_is_found(): void {
        $this->resetAfterTest();
        $path = $this->ooxml([], 'application/vnd.ms-excel.sheet.macroEnabled.main+xml');
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($path, 'budget.xlsx')[0]);
    }

    public function test_old_office_file_with_vba_storage_is_found(): void {
        $this->resetAfterTest();
        $ole = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" . str_repeat("\0", 504) .
            mb_convert_encoding('Root Entry', 'UTF-16LE') . str_repeat("\0", 100) .
            mb_convert_encoding('_VBA_PROJECT', 'UTF-16LE') . str_repeat("\0", 100);
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($this->file($ole), 'report.doc')[0]);

        $plain = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" . str_repeat("\0", 504) .
            mb_convert_encoding('Root Entry', 'UTF-16LE') . str_repeat("\0", 100) .
            mb_convert_encoding('WordDocument', 'UTF-16LE');
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file($plain), 'report.doc')[0]);
    }

    public function test_pdf_with_javascript_or_launch_is_found(): void {
        $this->resetAfterTest();
        foreach (
            [
            '/OpenAction << /S /JavaScript /JS (app.alert\(1\)) >>',
            '/OpenAction << /S /Launch /F (cmd.exe) >>',
            '/Names << /J#61vaScript 3 0 R >>',
            ] as $extra
        ) {
            $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($this->file($this->pdf($extra)), 'x.pdf')[0], $extra);
        }
    }

    public function test_pdf_javascript_hidden_in_a_compressed_stream_is_found(): void {
        $this->resetAfterTest();
        $hidden = gzcompress('<< /S /JavaScript /JS (this.exportDataObject\(\)) >>');
        $pdf = "%PDF-1.7\n3 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length " . strlen($hidden) . " >>\nstream\n" .
            $hidden . "\nendstream\nendobj\n" . $this->pdf();
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($this->file($pdf), 'scan.pdf')[0]);
    }

    public function test_a_parenthesis_hidden_in_a_stream_cannot_hide_javascript(): void {
        $this->resetAfterTest();
        $pdf = "%PDF-1.7\n5 0 obj\n<< /Length 4 >>\nstream\nab (\nendstream\nendobj\n" .
            "1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS <6170702E616C657274283129> >> >>\nendobj\n" .
            "6 0 obj\n<< /Length 2 >>\nstream\n)\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($this->file($pdf), 'trick.pdf')[0]);
    }

    public function test_javascript_in_an_uncompressed_object_stream_is_found(): void {
        $this->resetAfterTest();
        $objects = '<< /S /JavaScript /JS <61> >>';
        $pdf = "%PDF-1.7\n3 0 obj\n<< /Type /ObjStm /Length " . strlen($objects) . " >>\nstream\n" . $objects .
            "\nendstream\nendobj\n" . $this->pdf();
        $this->assertSame(scanner::SCAN_RESULT_FOUND, $this->scan($this->file($pdf), 'objstm.pdf')[0]);
    }

    public function test_image_bytes_that_happen_to_spell_js_pass(): void {
        $this->resetAfterTest();
        $jpeg = "\xFF\xD8\xFF\xE0 random /JS( bytes \x95\xAA /JavaScript ]\xFF\xD9";
        $pdf = "%PDF-1.7\n7 0 obj\n<< /Type /XObject /Subtype /Image /Filter /DCTDecode /Length " . strlen($jpeg) .
            " >>\nstream\n" . $jpeg . "\nendstream\nendobj\n" . $this->pdf();
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file($pdf), 'photo.pdf')[0]);
    }

    public function test_a_pdf_that_only_talks_about_javascript_passes(): void {
        $this->resetAfterTest();
        $content = gzcompress("BT /F1 12 Tf 72 712 Td (Lecture 4: /JavaScript, /JS and /Launch in PDF files) Tj ET");
        $pdf = "%PDF-1.7\n4 0 obj\n<< /Filter /FlateDecode /Length " . strlen($content) . " >>\nstream\n" . $content .
            "\nendstream\nendobj\n" . $this->pdf('/Title (Notes on /JavaScript)');
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file($pdf), 'lecture4.pdf')[0]);
    }

    public function test_an_old_word_file_that_mentions_macros_in_its_text_passes(): void {
        $this->resetAfterTest();
        $doc = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" . str_repeat("\0", 504) .
            mb_convert_encoding('Root Entry', 'UTF-16LE') . "\0\0" .
            mb_convert_encoding('Excel Macros and _VBA_PROJECT basics', 'UTF-16LE') . "\r\0";
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file($doc), 'notes.doc')[0]);
    }

    public function test_checks_can_be_turned_off(): void {
        $this->resetAfterTest();
        set_config('blockmacros', 0, 'antivirus_activecontent');
        set_config('blockpdfjs', 0, 'antivirus_activecontent');
        $this->assertSame(
            scanner::SCAN_RESULT_OK,
            $this->scan($this->ooxml(['word/vbaProject.bin' => 'x']), 'a.docx')[0]
        );
        $this->assertSame(
            scanner::SCAN_RESULT_OK,
            $this->scan($this->file($this->pdf('/OpenAction << /S /JavaScript /JS (x) >>')), 'a.pdf')[0]
        );
    }

    public function test_a_broken_zip_is_not_an_error(): void {
        $this->resetAfterTest();
        $this->assertSame(scanner::SCAN_RESULT_OK, $this->scan($this->file("PK\x03\x04 not really a zip"), 'a.docx')[0]);
    }

    public function test_moodle_refuses_the_upload_with_our_reason(): void {
        $this->resetAfterTest();
        set_config('antiviruses', 'activecontent');
        $path = $this->ooxml(['xl/vbaProject.bin' => 'x']);
        try {
            \core\antivirus\manager::scan_file($path, 'grades.xlsx', true);
            $this->fail('The upload should have been refused');
        } catch (\core\antivirus\scanner_exception $e) {
            $this->assertStringContainsString('grades.xlsx', $e->getMessage());
            $this->assertStringContainsString('macro', $e->getMessage());
        }
        $this->assertFileDoesNotExist($path, 'Moodle deletes the refused upload');
    }
}
