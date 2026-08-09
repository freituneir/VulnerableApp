package org.sasanlabs.service.email;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.mail.MessagingException;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.apache.commons.lang3.StringUtils;
import org.sasanlabs.configuration.EmailConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailServiceImpl.class);
    private static final String RESET_PASSWORD_PATH = "/reset-password?token=";
    private static final String VERIFY_EMAIL_PATH = "/verify-email?token=";

    private final JavaMailSender javaMailSender;
    private final EmailConfiguration emailConfiguration;

    public EmailServiceImpl(JavaMailSender javaMailSender, EmailConfiguration emailConfiguration) {
        this.javaMailSender = javaMailSender;
        this.emailConfiguration = emailConfiguration;
    }

    @Override
    public void sendEmail(String to, String subject, String body) {
        validateEmailInputs(to, subject, body, "body");
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(emailConfiguration.getFrom());
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        send(() -> javaMailSender.send(message), to);
    }

    /**
     * Sends an HTML message, and treats a mail server that will not take it as a delivery problem
     * rather than as a failure of whatever asked for the mail.
     *
     * <p>This used to call {@code send} outside any handler, so an unreachable or unauthenticated
     * SMTP host turned every caller into a server error. That matters most for the password reset
     * flow: the request endpoint has to answer the same way whether or not an account exists, and a
     * 500 raised while delivering the mail told a caller both that the account existed and that the
     * reset had got as far as sending, which is exactly the distinction the generic response is
     * there to hide. It also made the whole flow unusable in any deployment without a mail server.
     * The message has already been persisted by the time delivery is attempted, so swallowing a
     * delivery failure loses nothing but the mail itself, which is logged.
     *
     * <p>The formatting failure below now returns instead of falling through: sending a
     * half-populated message with no recipient would only have raised a second, more confusing
     * error.
     */
    @Override
    public void sendHtmlEmail(String to, String subject, String htmlBody) {
        validateEmailInputs(to, subject, htmlBody, "htmlBody");
        MimeMessage message = javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(emailConfiguration.getFrom());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody, true);
        } catch (MessagingException ex) {
            LOGGER.warn("Unable to build the message addressed to {}", to, ex);
            return;
        }
        send(() -> javaMailSender.send(message), to);
    }

    /**
     * Runs a delivery attempt and downgrades any mail layer failure to a warning. {@link
     * MailException} is the root of the hierarchy, so this covers an unreachable host ({@link
     * MailSendException}), a rejected login and a message the sender refuses to prepare alike.
     */
    private void send(Runnable delivery, String to) {
        try {
            delivery.run();
        } catch (MailException ex) {
            LOGGER.warn("Mail server unavailable while sending email to {}", to, ex);
        }
    }

    @Override
    public void sendResetEmail(String to, String token) {
        requireText(token, "token");
        String resetUrl = buildUrl(RESET_PASSWORD_PATH, token);
        sendEmail(
                to,
                "VulnerableApp password reset",
                "Use the following link to reset your password: " + resetUrl);
    }

    @Override
    public void sendVerificationEmail(String to, String token) {
        requireText(token, "token");
        String verificationUrl = buildUrl(VERIFY_EMAIL_PATH, token);
        sendEmail(
                to,
                "VulnerableApp email verification",
                "Use the following link to verify your email address: " + verificationUrl);
    }

    private String buildUrl(String path, String token) {
        String baseUrl = emailConfiguration.getBaseUrl();
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + path + URLEncoder.encode(token, StandardCharsets.UTF_8);
    }

    private void validateEmailInputs(
            String to, String subject, String content, String contentName) {
        requireEmailAddress(to);
        requireText(subject, "subject");
        requireNonNull(content, contentName);
        requireEmailAddress(emailConfiguration.getFrom());
    }

    private void requireEmailAddress(String emailAddress) {
        requireText(emailAddress, "email address");
        try {
            InternetAddress internetAddress = new InternetAddress(emailAddress, true);
            internetAddress.validate();
        } catch (AddressException ex) {
            throw new IllegalArgumentException("Invalid email address: " + emailAddress, ex);
        }
    }

    private void requireText(String value, String fieldName) {
        if (StringUtils.isBlank(value)) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }

    private void requireNonNull(String value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " must not be null");
        }
    }
}
