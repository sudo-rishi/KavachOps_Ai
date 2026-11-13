package com.kavachopsai.config;

import java.util.concurrent.Executor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import com.kavachopsai.service.NetworkAnalysisService;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class AsyncConfig implements SchedulingConfigurer {

    private final NetworkAnalysisService networkAnalysisService;

    /** Async thread pool for packet capture processing */
    @Bean(name = "captureExecutor")
    public Executor captureExecutor() {
        ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
        exec.setCorePoolSize(4);
        exec.setMaxPoolSize(8);
        exec.setQueueCapacity(1000);
        exec.setThreadNamePrefix("capture-");
        exec.setWaitForTasksToCompleteOnShutdown(true);
        exec.setAwaitTerminationSeconds(10);
        exec.initialize();
        return exec;
    }

    /** General async executor */
    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
        exec.setCorePoolSize(2);
        exec.setMaxPoolSize(4);
        exec.setQueueCapacity(200);
        exec.setThreadNamePrefix("shield-task-");
        exec.initialize();
        return exec;
    }

    /** Dedicated executor for long-running vulnerability scan loops */
    @Bean(name = "scanExecutor")
    public TaskExecutor scanExecutor() {
        ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
        exec.setCorePoolSize(4);
        exec.setMaxPoolSize(12);
        exec.setQueueCapacity(500);
        exec.setThreadNamePrefix("shield-scan-");
        exec.initialize();
        return exec;
    }

    /** Scheduler for @Scheduled tasks */
    @SuppressWarnings("deprecation")
    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(4);
        scheduler.setThreadNamePrefix("shield-sched-");
        scheduler.initialize();
        registrar.setTaskScheduler(scheduler);

        // Drain the packet queue every 500ms
        registrar.addFixedDelayTask(networkAnalysisService::drainQueue, 500);
    }
}

